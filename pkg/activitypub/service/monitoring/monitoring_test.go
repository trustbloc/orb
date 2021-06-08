/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring_test

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	. "github.com/trustbloc/orb/pkg/activitypub/service/monitoring"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	storeName       = "monitoring"
	tagNotConfirmed = "not_confirmed"
)

func TestNew(t *testing.T) {
	client, err := New(mem.NewProvider(), nil)
	require.NoError(t, err)
	require.NotNil(t, client)

	client.Close()

	client, err = New(&mockstore.Provider{ErrOpenStore: errors.New("error")}, nil)
	require.EqualError(t, err, "open store: error")
	require.Nil(t, client)

	client, err = New(&mockstore.Provider{ErrSetStoreConfig: errors.New("error")}, nil)
	require.EqualError(t, err, "failed to set store configuration: error")
	require.Nil(t, client)
}

func TestNext(t *testing.T) {
	require.False(t, Next(&mockNext{err: errors.New("error")}))
	require.True(t, Next(&mockNext{}))
}

func TestClient_Watch(t *testing.T) {
	t.Run("Expired", func(t *testing.T) {
		client, err := New(mem.NewProvider(), nil)
		require.NoError(t, err)

		require.EqualError(t, client.Watch(&verifiable.Credential{},
			time.Now().Add(-time.Minute),
			"https://vct.com", time.Now(),
		), "expired")
	})

	t.Run("Escape to queue (two entities)", func(t *testing.T) {
		db := mem.NewProvider()

		client, err := New(db, testutil.GetLoader(t), WithHTTPClient(&http.Client{Timeout: time.Second}))
		require.NoError(t, err)

		ID1 := "https://orb.domain.com/" + uuid.New().String()
		ID2 := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID1,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID1,
			Issuer:  verifiable.Issuer{ID: ID1},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID2,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID2,
			Issuer:  verifiable.Issuer{ID: ID2},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 2)
	})

	t.Run("Escape to queue", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/ct/v1/get-sth" {
				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 1)
	})

	t.Run("No audit path (escapes to queue)", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"audit_path":[]}`)),
				StatusCode: http.StatusOK,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 1)
	})

	t.Run("Worker handles queue", func(t *testing.T) {
		proceed := make(chan struct{})

		db := newDBMock(t)
		db.mockStore.errQuery = func() error {
			db.mockStore.errQuery = nil
			close(proceed)

			return errors.New("error")
		}

		store, err := db.OpenStore(storeName)
		require.NoError(t, err)

		responses := make(chan string, 4)
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{"audit_path":[[]]}`

		dl := testutil.GetLoader(t)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(<-responses)),
				StatusCode: http.StatusOK,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"", time.Now(),
		))

		require.NoError(t, backoff.Retry(func() error {
			select {
			case <-proceed:
			case <-time.After(time.Second * 3):
				t.Error("timeout")
			}

			records, err := store.Query(tagNotConfirmed)
			if err != nil {
				return err
			}

			var count int
			for Next(records) {
				count++
			}

			if count != 0 {
				return errors.New("expecting empty queue")
			}

			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3)))
		checkQueue(t, db, 0)
	})

	t.Run("Worker handles queue (expired)", func(t *testing.T) {
		db := newDBMock(t)
		db.mockStore.errDelete = func() error {
			db.mockStore.errDelete = nil

			return errors.New("error")
		}

		store, err := db.OpenStore(storeName)
		require.NoError(t, err)

		responses := make(chan string, 6)
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`

		dl := testutil.GetLoader(t)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(<-responses)),
				StatusCode: http.StatusOK,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Millisecond*100),
			"https://vct.com", time.Now()),
		)

		require.NoError(t, backoff.Retry(func() error {
			records, err := store.Query(tagNotConfirmed)
			require.NoError(t, err)

			var count int
			for Next(records) {
				count++
			}

			if count != 0 {
				return errors.New("expecting empty queue")
			}

			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3)))
		checkQueue(t, db, 0)
		require.Nil(t, db.mockStore.errDelete)
	})

	t.Run("Success", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"audit_path":[[]]}`)),
				StatusCode: http.StatusOK,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"", time.Now(),
		))

		checkQueue(t, db, 0)
	})

	t.Run("Marshal credential (error)", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		client, err := New(db, dl, WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"audit_path":[[]]}`)),
				StatusCode: http.StatusOK,
			}, nil
		})))
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.EqualError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: make(chan int),
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWithTrailingZeroMsec{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		), "marshal credential: JSON marshalling of verifiable credential: subject of unknown structure")

		checkQueue(t, db, 0)
	})
}

func checkQueue(t *testing.T, db storage.Provider, expected int) {
	t.Helper()

	store, err := db.OpenStore(storeName)
	require.NoError(t, err)

	records, err := store.Query(tagNotConfirmed)
	require.NoError(t, err)

	var count int
	for Next(records) {
		count++
	}

	require.Equal(t, count, expected)
}

type dbMock struct {
	storage.Provider
	mockStore *dbMockStore
}

func newDBMock(t *testing.T) *dbMock {
	t.Helper()

	p := mem.NewProvider()
	store, err := p.OpenStore("mock-db")
	require.NoError(t, err)

	return &dbMock{
		Provider:  p,
		mockStore: &dbMockStore{Store: store, mu: &sync.Mutex{}},
	}
}

type dbMockStore struct {
	storage.Store
	mu        *sync.Mutex
	errQuery  func() error
	errDelete func() error
}

func (m *dbMockStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errDelete != nil {
		return m.errDelete()
	}

	return m.Store.Delete(key)
}

func (m *dbMockStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.errQuery != nil {
		return nil, m.errQuery()
	}

	return m.Store.Query(expression, options...)
}

func (m *dbMock) OpenStore(_ string) (storage.Store, error) {
	return m.mockStore, nil
}

func (m *dbMock) SetStoreConfig(string, storage.StoreConfiguration) error {
	return nil
}

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}

type mockNext struct{ err error }

func (m *mockNext) Next() (bool, error) {
	return true, m.err
}
