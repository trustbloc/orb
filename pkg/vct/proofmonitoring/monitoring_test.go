/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proofmonitoring_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	. "github.com/trustbloc/orb/pkg/vct/proofmonitoring"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	storeName         = "proof-monitor"
	tagStatus         = "status"
	statusUnconfirmed = "unconfirmed"

	webfingerPayload = `{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct-v1"}}`
)

func TestNew(t *testing.T) {
	taskMgr := mocks.NewTaskManager("vct-monitor")

	client, err := New(mem.NewProvider(), nil, nil, nil, taskMgr, time.Second, map[string]string{})
	require.NoError(t, err)
	require.NotNil(t, client)

	client, err = New(&mockstore.Provider{ErrOpenStore: errors.New("error")}, nil, nil, nil,
		taskMgr, time.Second, map[string]string{})
	require.EqualError(t, err, "open store: open store [proof-monitor]: error")
	require.Nil(t, client)

	client, err = New(&mockstore.Provider{ErrSetStoreConfig: errors.New("error")}, nil, nil, nil,
		taskMgr, time.Second, map[string]string{})
	require.EqualError(t, err, "open store: set store configuration for [proof-monitor]: error")
	require.Nil(t, client)
}

func TestNext(t *testing.T) {
	require.False(t, Next(&mockNext{err: errors.New("error")}))
	require.True(t, Next(&mockNext{}))
}

func TestClient_Watch(t *testing.T) { //nolint:cyclop,maintidx
	wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	httpClient := &http.Client{Timeout: time.Second}

	t.Run("Expired", func(t *testing.T) {
		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(mem.NewProvider(), nil, wfClient, httpClient, taskMgr,
			time.Second, map[string]string{})
		require.NoError(t, err)

		require.EqualError(t, client.Watch(&verifiable.Credential{},
			time.Now().Add(-time.Minute),
			"https://vct.com", time.Now(),
		), "expired")
	})

	t.Run("Escape to queue (two entities)", func(t *testing.T) {
		db := mem.NewProvider()

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(db, testutil.GetLoader(t), wfClient, httpClient, taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID1 := "https://orb.domain.com/" + uuid.New().String()
		ID2 := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID1,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID1,
			Issuer:  verifiable.Issuer{ID: ID1},
			Issued:  &util.TimeWrapper{},
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
			Issued:  &util.TimeWrapper{},
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

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/ct/v1/get-sth" {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 1)
	})

	t.Run("Proof found -> success", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		var callNum int

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			switch callNum {
			case 0:
				callNum++

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{"tree_size":1}`)),
					StatusCode: http.StatusOK,
				}, nil
			case 1:
				callNum++

				return &http.Response{
					Body: io.NopCloser(bytes.NewBufferString(
						`{"leaf_index":1,"audit_path":["r7LiyrC61FBM2ylSs+V8o5r+9wppzAH0DYHbOqhYnl4="]}`)),
					StatusCode: http.StatusOK,
				}, nil
			default:
				return nil, errors.New("unexpected HTTP request")
			}
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 0)
	})

	t.Run("Tree size is 0 (escapes to queue)", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{"tree_size":0}`)),
				StatusCode: http.StatusOK,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		))

		checkQueue(t, db, 1)
	})

	t.Run("No proof (escapes to queue)", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		var callNum int

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			switch callNum {
			case 0:
				callNum++

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{"tree_size":1}`)),
					StatusCode: http.StatusOK,
				}, nil
			case 1:
				callNum++

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`Not found`)),
					StatusCode: http.StatusNotFound,
				}, nil
			default:
				return nil, errors.New("unexpected HTTP request")
			}
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
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

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		var callNum int

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			switch callNum {
			case 0:
				callNum++

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{"tree_size":1}`)),
					StatusCode: http.StatusOK,
				}, nil
			case 1:
				callNum++

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{"leaf_index":1}`)),
					StatusCode: http.StatusOK,
				}, nil
			default:
				return nil, errors.New("unexpected HTTP request")
			}
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
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

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(<-responses)),
				StatusCode: http.StatusOK,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
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

			records, err := store.Query(fmt.Sprintf("%s:%s", tagStatus, statusUnconfirmed))
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

		responses := make(chan string, 7)
		responses <- webfingerPayload
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`
		responses <- `{}`

		dl := testutil.GetLoader(t)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		taskMgr.Start()
		defer taskMgr.Stop()

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(<-responses)),
				StatusCode: http.StatusOK,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Millisecond*100),
			"https://vct.com", time.Now()),
		)

		require.NoError(t, backoff.Retry(func() error {
			records, err := store.Query(fmt.Sprintf("%s:%s", tagStatus, statusUnconfirmed))
			require.NoError(t, err)

			var count int
			for Next(records) {
				count++
			}

			if count != 0 {
				return errors.New("expecting empty queue")
			}

			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 4)))
		checkQueue(t, db, 0)
		require.Nil(t, db.mockStore.errDelete)
	})

	t.Run("Success", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{"audit_path":[[]]}`)),
				StatusCode: http.StatusOK,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: ID,
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
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

		taskMgr := mocks.NewTaskManager("vct-monitor")

		client, err := New(db, dl, wfClient, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{"audit_path":[[]]}`)),
				StatusCode: http.StatusOK,
			}, nil
		}), taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.EqualError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: make(chan int),
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		), "marshal credential: JSON marshalling of verifiable credential: subject of unknown structure")

		checkQueue(t, db, 0)
	})

	t.Run("Webfinger (internal server error)", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		notFoundWebfingerClient := wfclient.New(wfclient.WithHTTPClient(
			httpMock(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("internal server error")),
					StatusCode: http.StatusInternalServerError,
				}, nil
			})))

		client, err := New(db, dl, notFoundWebfingerClient, httpClient, taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.EqualError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: make(chan int),
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		), "get ledger type: failed to resolve WebFinger resource[https://vct.com]: get webfinger resource for domain"+
			" [https://vct.com] and resource [https://vct.com]: received unexpected status code."+
			" URL [https://vct.com/.well-known/webfinger?resource=https://vct.com], status code [500],"+
			" response body [internal server error]")

		checkQueue(t, db, 0)
	})

	t.Run("No ledger type property", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		noLegerTypeWebfingerClient := wfclient.New(wfclient.WithHTTPClient(
			httpMock(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
					StatusCode: http.StatusOK,
				}, nil
			})))

		client, err := New(db, dl, noLegerTypeWebfingerClient, httpClient, taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: make(chan int),
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
			Types:   []string{"VerifiableCredential"},
		},
			time.Now().Add(time.Minute),
			"https://vct.com", time.Now(),
		), "marshal credential: JSON marshalling of verifiable credential: subject of unknown structure")

		checkQueue(t, db, 0)
	})

	t.Run("Unsupported ledger type", func(t *testing.T) {
		var (
			db = mem.NewProvider()
			dl = testutil.GetLoader(t)
		)

		taskMgr := mocks.NewTaskManager("vct-monitor")

		wrongLegerTypeWebfingerClient := wfclient.New(wfclient.WithHTTPClient(
			httpMock(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Body: io.NopCloser(
						bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
					),
					StatusCode: http.StatusOK,
				}, nil
			})))

		client, err := New(db, dl, wrongLegerTypeWebfingerClient, httpClient, taskMgr, time.Second, map[string]string{})
		require.NoError(t, err)

		ID := "https://orb.domain.com/" + uuid.New().String()

		require.NoError(t, client.Watch(&verifiable.Credential{
			ID:      ID,
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			Subject: make(chan int),
			Issuer:  verifiable.Issuer{ID: ID},
			Issued:  &util.TimeWrapper{},
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

	records, err := store.Query(fmt.Sprintf("%s:%s", tagStatus, statusUnconfirmed))
	require.NoError(t, err)

	var count int
	for Next(records) {
		count++
	}

	require.Equal(t, expected, count)
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
