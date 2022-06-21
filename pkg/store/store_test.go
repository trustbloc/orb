/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ./mocks/mongodbprovider.gen.go --fake-name MongoDBProvider . mongoDBTestProvider
//go:generate counterfeiter -o ./mocks/mongodbstore.gen.go --fake-name MongoDBStore . mongoDBTestStore
//go:generate counterfeiter -o ./mocks/mongodbiterator.gen.go --fake-name MongoDBIterator github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb.Iterator

// mongoDBTestProvider is used to generate the mock MongoDBProvider.
//nolint:deadcode,unused
type mongoDBTestProvider interface {
	storage.Provider
	mongoDBProvider

	Ping() error
}

// mongoDBTestStore is used to generate the mock MongoDBStore.
//nolint:deadcode,unused
type mongoDBTestStore interface {
	storage.Store
	mongoDBStore
}

func TestOpen(t *testing.T) {
	const (
		tag1 = "tag1"
		tag2 = "tag2"
		tag3 = "tag3"
	)

	t.Run("Standard store", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			store := &mocks.Store{}

			provider := &mocks.Provider{}
			provider.OpenStoreReturns(store, nil)

			s, err := Open(provider, "store1",
				NewTagGroup(tag1, tag2),
				NewTagGroup(tag3),
			)
			require.NoError(t, err)
			require.NotNil(t, s)
		})

		t.Run("SetStoreConfig error", func(t *testing.T) {
			errExpected := errors.New("injected SetStoreConfig error")

			store := &mocks.Store{}

			provider := &mocks.Provider{}
			provider.OpenStoreReturns(store, nil)
			provider.SetStoreConfigReturns(errExpected)

			s, err := Open(provider, "store1",
				NewTagGroup(tag1, tag2),
				NewTagGroup(tag3),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
			require.Nil(t, s)
		})
	})

	t.Run("MongoDB store", func(t *testing.T) {
		t.Run("No tags -> success", func(t *testing.T) {
			store := &mocks.MongoDBStore{}

			provider := &mocks.MongoDBProvider{}
			provider.OpenStoreReturns(store, nil)

			s, err := Open(provider, "store1")
			require.NoError(t, err)
			require.NotNil(t, s)
		})

		t.Run("With tags -> success", func(t *testing.T) {
			store := &mocks.MongoDBStore{}

			provider := &mocks.MongoDBProvider{}
			provider.OpenStoreReturns(store, nil)

			s, err := Open(provider, "store1",
				NewTagGroup(tag1, tag2),
				NewTagGroup(tag3),
			)
			require.NoError(t, err)
			require.NotNil(t, s)
		})

		t.Run("Non-MongoDB store for MongoDB provider -> error", func(t *testing.T) {
			store := &mocks.Store{}

			provider := &mocks.MongoDBProvider{}
			provider.OpenStoreReturns(store, nil)

			require.Panics(t, func() {
				_, err := Open(provider, "store1",
					NewTagGroup(tag1, tag2),
					NewTagGroup(tag3),
				)
				require.NoError(t, err)
			})
		})

		t.Run("CreateIndexes error", func(t *testing.T) {
			errExpected := errors.New("injected CreateCustomIndex error")

			store := &mocks.MongoDBStore{}

			provider := &mocks.MongoDBProvider{}
			provider.OpenStoreReturns(store, nil)
			provider.CreateCustomIndexesReturns(errExpected)

			s, err := Open(provider, "store1",
				NewTagGroup(tag1, tag2),
				NewTagGroup(tag3),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
			require.Nil(t, s)
		})
	})

	t.Run("OpenStore error", func(t *testing.T) {
		errExpected := errors.New("injected OpenStore error")
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, errExpected)

		s, err := Open(provider, "store1",
			NewTagGroup(tag1, tag2),
			NewTagGroup(tag3),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestMongoDBPut(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	const key = "key1"

	t.Run("success", func(t *testing.T) {
		require.NoError(t, s.Put(key, []byte(`{}`)))
	})

	t.Run("unmarshal error", func(t *testing.T) {
		require.Error(t, s.Put(key, []byte(`{`)))
	})

	t.Run("PutAsJSON error", func(t *testing.T) {
		errExpected := errors.New("injected PutAsJSON error")

		store.PutAsJSONReturns(errExpected)

		err := s.Put(key, []byte(`{}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestMongoDBGet(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	const key = "key1"

	t.Run("success", func(t *testing.T) {
		store.GetAsRawMapReturns(map[string]interface{}{key: "value1"}, nil)

		docBytes, err := s.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, docBytes)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(docBytes, &doc))
		require.Equal(t, "value1", doc[key])
	})

	t.Run("marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		s.(*mongoDBWrapper).marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}
		defer func() {
			s.(*mongoDBWrapper).marshal = json.Marshal
		}()

		docBytes, err := s.Get(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, docBytes)
	})

	t.Run("GetAsRawMap error", func(t *testing.T) {
		errExpected := errors.New("injected GetAsRawMap error")

		store.GetAsRawMapReturns(nil, errExpected)

		docBytes, err := s.Get(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, docBytes)
	})
}

func TestMongoDBGetBulk(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	const (
		key1 = "key1"
		key2 = "key2"
	)

	t.Run("success", func(t *testing.T) {
		store.GetBulkAsRawMapReturns([]map[string]interface{}{
			{key1: "value1"},
			{key2: "value2"},
		}, nil)

		docBytes, err := s.GetBulk(key1, key2)
		require.NoError(t, err)
		require.Len(t, docBytes, 2)

		var doc map[string]interface{}

		require.NoError(t, json.Unmarshal(docBytes[0], &doc))
		require.Equal(t, "value1", doc[key1])

		require.NoError(t, json.Unmarshal(docBytes[1], &doc))
		require.Equal(t, "value2", doc[key2])
	})

	t.Run("marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		s.(*mongoDBWrapper).marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}
		defer func() {
			s.(*mongoDBWrapper).marshal = json.Marshal
		}()

		store.GetBulkAsRawMapReturns([]map[string]interface{}{
			{key1: "value1"},
			{key2: "value2"},
		}, nil)

		docBytes, err := s.GetBulk(key1, key2)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, docBytes)
	})

	t.Run("GetBulkAsRawMapReturns error", func(t *testing.T) {
		errExpected := errors.New("injected GetBulkAsRawMapReturns error")

		store.GetBulkAsRawMapReturns(nil, errExpected)

		docBytes, err := s.GetBulk(key1, key2)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, docBytes)
	})
}

func TestMongoDBQuery(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("success", func(t *testing.T) {
		mit := &mocks.MongoDBIterator{}
		mit.NextReturns(true, nil)
		mit.ValueAsRawMapReturns(map[string]interface{}{"field1": "value1"}, nil)

		store.QueryCustomReturns(mit, nil)

		it, err := s.Query("field1:value1")
		require.NoError(t, err)
		require.NotNil(t, it)

		ok, err := it.Next()
		require.NoError(t, err)
		require.True(t, ok)

		value, err := it.Value()
		require.NoError(t, err)
		require.NotEmpty(t, value)

		var doc map[string]interface{}

		require.NoError(t, json.Unmarshal(value, &doc))
		require.Equal(t, "value1", doc["field1"])
	})

	t.Run("invalid expression", func(t *testing.T) {
		it, err := s.Query(">")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid syntax")
		require.Nil(t, it)
	})

	t.Run("QueryCustom error", func(t *testing.T) {
		errExpected := errors.New("injected QueryCustom error")

		store.QueryCustomReturns(nil, errExpected)

		it, err := s.Query("x:y")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, it)
	})

	t.Run("Iterator error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		mit := &mocks.MongoDBIterator{}
		mit.NextReturns(true, nil)
		mit.ValueAsRawMapReturns(nil, errExpected)

		store.QueryCustomReturns(mit, nil)

		it, err := s.Query("x:y")
		require.NoError(t, err)
		require.NotNil(t, it)

		_, err = it.Value()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Iterator marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		mit := &mocks.MongoDBIterator{}
		mit.NextReturns(true, nil)
		mit.ValueAsRawMapReturns(map[string]interface{}{"field1": "value1"}, nil)

		store.QueryCustomReturns(mit, nil)

		it, err := s.Query("x:y")
		require.NoError(t, err)
		require.NotNil(t, it)

		it.(*mongoDBIteratorWrapper).marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		_, err = it.Value()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestMongoDBGetTags(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	require.Panics(t, func() {
		_, err := s.GetTags("key")
		require.NoError(t, err)
	})
}

func TestMongoDBBatch(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")

	require.NoError(t, err)
	require.NotNil(t, s)

	const (
		key1 = "key1"
		key2 = "key2"
		key3 = "key3"
	)

	t.Run("success", func(t *testing.T) {
		require.NoError(t, s.Batch([]storage.Operation{
			{
				Key:   key1,
				Value: []byte(`{"field1":"value1"}`),
			},
			{
				Key:        key2,
				Value:      []byte(`{"field1":"value2"}`),
				PutOptions: &storage.PutOptions{IsNewKey: true},
			},
			{
				Key: key3,
			},
		}))
	})

	t.Run("unmarshal error", func(t *testing.T) {
		require.Error(t, s.Batch([]storage.Operation{
			{
				Key:   key1,
				Value: []byte(`{`),
			},
		}))
	})

	t.Run("BulkWrite error", func(t *testing.T) {
		errExpected := errors.New("injected BulkWrite error")

		store.BulkWriteReturns(errExpected)

		err := s.Batch([]storage.Operation{
			{
				Key:   key1,
				Value: []byte(`{"field1":"value1"}`),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestMongoDBNoOverrides(t *testing.T) {
	store := &mocks.MongoDBStore{}

	provider := &mocks.MongoDBProvider{}
	provider.OpenStoreReturns(store, nil)

	s, err := Open(provider, "store1")
	require.NoError(t, err)
	require.NotNil(t, s)

	require.NoError(t, s.Delete("key1"))
	require.NoError(t, s.Flush())
	require.NoError(t, s.Close())
}
