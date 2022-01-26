/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestSyncStore_New(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s, err := newSyncStore(storage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("Error", func(t *testing.T) {
		p := storage.NewMockStoreProvider()

		errExpected := errors.New("injected open store error")

		p.ErrOpenStoreHandle = errExpected

		s, err := newSyncStore(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestSyncStore_GetAndPut(t *testing.T) {
	var (
		page0 = testutil.MustParseURL("https://domain1.com/services/orb/outbox?page=true&page-num=0")
		page1 = testutil.MustParseURL("https://domain2.com/services/orb/outbox?page=true&page-num=1")

		service1IRI = testutil.MustParseURL("https://domain1.com/services/orb")
		service2IRI = testutil.MustParseURL("https://domain2.com/services/orb")
	)

	p := storage.NewMockStoreProvider()

	p.Store = &storage.MockStore{
		Store: make(map[string]storage.DBEntry),
	}

	s, err := newSyncStore(p)
	require.NoError(t, err)
	require.NotNil(t, s)

	require.NoError(t, s.PutLastSyncedPage(service1IRI, outbox, page0, 3))
	require.NoError(t, err)

	require.NoError(t, s.PutLastSyncedPage(service2IRI, outbox, page1, 4))
	require.NoError(t, err)

	page, index, err := s.GetLastSyncedPage(service1IRI, outbox)
	require.NoError(t, err)
	require.Equal(t, page0.String(), page.String())
	require.Equal(t, 3, index)

	page, index, err = s.GetLastSyncedPage(service2IRI, outbox)
	require.NoError(t, err)
	require.Equal(t, page1.String(), page.String())
	require.Equal(t, 4, index)
}

func TestSyncStore_Error(t *testing.T) {
	var (
		serviceIRI = testutil.MustParseURL("https://domain1.com/services/orb")
		page       = testutil.MustParseURL("https://domain1.com/services/orb/outbox?page=true&page-num=0")
	)

	p := storage.NewMockStoreProvider()

	t.Run("Get error", func(t *testing.T) {
		errExpected := errors.New("injected Get error")

		p.Store = &storage.MockStore{
			ErrGet: errExpected,
			Store:  make(map[string]storage.DBEntry),
		}

		s, err := newSyncStore(p)
		require.NoError(t, err)
		require.NotNil(t, s)

		_, _, err = s.GetLastSyncedPage(serviceIRI, outbox)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		errExpected := errors.New("injected unmarshal error")

		p.Store = &storage.MockStore{
			Store: make(map[string]storage.DBEntry),
		}

		s, err := newSyncStore(p)
		require.NoError(t, err)
		require.NotNil(t, s)

		s.unmarshal = func(data []byte, v interface{}) error { return errExpected }

		require.NoError(t, s.PutLastSyncedPage(serviceIRI, outbox, page, 3))
		require.NoError(t, err)

		_, _, err = s.GetLastSyncedPage(serviceIRI, outbox)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("URL parse error", func(t *testing.T) {
		p.Store = &storage.MockStore{
			Store: make(map[string]storage.DBEntry),
		}

		info := &syncInfo{
			Page: ":",
		}

		infoBytes, err := json.Marshal(info)
		require.NoError(t, err)

		require.NoError(t, p.Store.Put(getKey(serviceIRI, outbox), infoBytes))

		s, err := newSyncStore(p)
		require.NoError(t, err)
		require.NotNil(t, s)

		_, _, err = s.GetLastSyncedPage(serviceIRI, outbox)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})

	t.Run("Put error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		p.Store = &storage.MockStore{
			ErrPut: errExpected,
			Store:  make(map[string]storage.DBEntry),
		}

		s, err := newSyncStore(p)
		require.NoError(t, err)
		require.NotNil(t, s)

		err = s.PutLastSyncedPage(serviceIRI, outbox, page, 3)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Mmarshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		p.Store = &storage.MockStore{
			Store: make(map[string]storage.DBEntry),
		}

		s, err := newSyncStore(p)
		require.NoError(t, err)
		require.NotNil(t, s)

		s.marshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		err = s.PutLastSyncedPage(serviceIRI, outbox, page, 3)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}
