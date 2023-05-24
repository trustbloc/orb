/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/context/mocks"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
)

//go:generate counterfeiter -o ../../mocks/expiryservice.gen.go --fake-name ExpiryService . dataExpiryService

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s, err := New(storage.NewMockStoreProvider(), &mocks.DataExpiryService{},
			WithPendingRecordLifespan(5*time.Minute))
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("Open store error", func(t *testing.T) {
		provider := storage.NewMockStoreProvider()

		errExpected := errors.New("injected open store error")

		provider.ErrOpenStoreHandle = errExpected

		s, err := New(provider, &mocks.DataExpiryService{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})

	t.Run("Open store error", func(t *testing.T) {
		provider := storage.NewMockStoreProvider()

		errExpected := errors.New("injected set config error")

		provider.ErrSetStoreConfig = errExpected

		s, err := New(provider, &mocks.DataExpiryService{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestStore_PutLinks(t *testing.T) {
	provider := storage.NewMockStoreProvider()

	s, err := New(provider, &mocks.DataExpiryService{})
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Success", func(t *testing.T) {
		const hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		const hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash1)
		link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodzZ4OVhtYkNTZjRfTWc", hash1)
		link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash2)

		require.NoError(t, s.PutLinks(
			[]*url.URL{
				testutil.MustParseURL(link1),
				testutil.MustParseURL(link2),
				testutil.MustParseURL(link3),
			},
		))
	})

	t.Run("Invalid hashlink", func(t *testing.T) {
		require.Error(t, s.PutLinks([]*url.URL{testutil.MustParseURL("https://xxx")}))
	})

	t.Run("Marshal error", func(t *testing.T) {
		s.marshal = func(i interface{}) ([]byte, error) { return nil, errors.New("injected marshal error") }
		defer func() { s.marshal = json.Marshal }()

		require.Error(t, s.PutLinks([]*url.URL{testutil.MustParseURL("hl:xxx")}))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		provider.Store.ErrBatch = errExpected

		err := s.PutLinks([]*url.URL{testutil.MustParseURL("hl:xxx")})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestStore_GetLinks(t *testing.T) {
	const (
		hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"
	)

	mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
	defer stopMongo()

	provider, err := mongodb.NewProvider(mongoDBConnString)
	require.NoError(t, err)

	s, err := New(provider, &mocks.DataExpiryService{})
	require.NoError(t, err)
	require.NotNil(t, s)

	link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodUZzbk1ucmdEa3NBdFEtd0NhS3c", hash1)
	link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodWJRbWI2SzZ4OVhtYkNTZjRfTWc", hash1)
	link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodUZzbk1ucmdEa3NBdFEtd0NhS3c", hash2)
	link4 := fmt.Sprintf("hl:%s:uoQ-BeEtodUZzbl1ucmdEa3NBdFEtd0NhS3c", hash2)

	require.NoError(t, s.PutLinks(
		[]*url.URL{
			testutil.MustParseURL(link1),
			testutil.MustParseURL(link2),
			testutil.MustParseURL(link3),
		},
	))

	require.NoError(t, s.PutPendingLinks(
		[]*url.URL{
			testutil.MustParseURL(link4),
		},
	))

	links, err := s.GetLinks(hash1)
	require.NoError(t, err)
	require.Len(t, links, 2)

	links, err = s.GetLinks(hash2)
	require.NoError(t, err)
	require.Len(t, links, 1)

	links, err = s.GetProcessedAndPendingLinks(hash2)
	require.NoError(t, err)
	require.Len(t, links, 2)
}

func TestStore_GetLinksError(t *testing.T) {
	const hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"

	provider := storage.NewMockStoreProvider()

	s, err := New(provider, &mocks.DataExpiryService{})
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Query error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		provider.Store.ErrQuery = errExpected
		defer func() { provider.Store.ErrQuery = nil }()

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Iterator.Next error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		provider.Store.ErrNext = errExpected
		defer func() { provider.Store.ErrNext = nil }()

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Iterator.Value error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		provider.Store.ErrValue = errExpected
		defer func() { provider.Store.ErrValue = nil }()

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodHRwczovL29yYi5kb0NhS3c", hash1)

		require.NoError(t, s.PutLinks([]*url.URL{testutil.MustParseURL(link1)}))

		links, err := s.GetProcessedAndPendingLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error { return errExpected }

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodHRwczovL29yYi5kb21hNhS3c", hash1)

		require.NoError(t, s.PutLinks([]*url.URL{testutil.MustParseURL(link1)}))

		links, err := s.GetProcessedAndPendingLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, orberrors.IsTransient(err))
	})
}

func TestStore_DeleteLinks(t *testing.T) {
	provider := storage.NewMockStoreProvider()

	s, err := New(provider, &mocks.DataExpiryService{})
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Success", func(t *testing.T) {
		const hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		const hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash1)
		link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodzZ4OVhtYkNTZjRfTWc", hash1)
		link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash2)

		require.NoError(t, s.DeleteLinks(
			[]*url.URL{
				testutil.MustParseURL(link1),
				testutil.MustParseURL(link2),
				testutil.MustParseURL(link3),
			},
		))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		provider.Store.ErrBatch = errExpected

		err := s.DeleteLinks([]*url.URL{testutil.MustParseURL("hl:xxx")})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestStore_HandleExpiredKeys(t *testing.T) {
	const (
		key1 = "key1"
		key2 = "key2"
		key3 = "key3"
	)

	t.Run("Success", func(t *testing.T) {
		s, err := New(storage.NewMockStoreProvider(), &mocks.DataExpiryService{},
			WithPendingRecordLifespan(5*time.Minute))
		require.NoError(t, err)
		require.NotNil(t, s)

		require.NoError(t, s.store.Put(key1, testutil.MarshalCanonical(t, &anchorLinkRef{Status: statusPending})))
		require.NoError(t, s.store.Put(key2, testutil.MarshalCanonical(t, &anchorLinkRef{Status: statusProcessed})))
		require.NoError(t, s.store.Put(key3, testutil.MarshalCanonical(t, &anchorLinkRef{Status: statusPending})))

		keys, err := s.HandleExpiredKeys(key1, key2, key3)
		require.NoError(t, err)
		require.Equal(t, []string{key1, key3}, keys)
	})

	t.Run("Store error", func(t *testing.T) {
		provider := storage.NewMockStoreProvider()
		provider.Store.ErrGet = errors.New("injected get error")

		s, err := New(provider, &mocks.DataExpiryService{},
			WithPendingRecordLifespan(5*time.Minute))
		require.NoError(t, err)
		require.NotNil(t, s)

		keys, err := s.HandleExpiredKeys(key1, key2, key3)
		require.Error(t, err)
		require.Contains(t, err.Error(), provider.Store.ErrGet.Error())
		require.Empty(t, keys)
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		s, err := New(storage.NewMockStoreProvider(), &mocks.DataExpiryService{},
			WithPendingRecordLifespan(5*time.Minute))
		require.NoError(t, err)
		require.NotNil(t, s)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error { return errExpected }

		require.NoError(t, s.store.Put(key1, testutil.MarshalCanonical(t, &anchorLinkRef{Status: statusPending})))

		keys, err := s.HandleExpiredKeys(key1)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, keys)
	})
}
