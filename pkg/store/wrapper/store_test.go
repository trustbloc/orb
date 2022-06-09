/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"testing"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

func TestStoreWrapper(t *testing.T) {
	s := NewStore(&ariesmockstorage.Store{}, "CouchDB")
	require.NotNil(t, s)

	t.Run("put", func(t *testing.T) {
		require.NoError(t, s.Put("k1", []byte("v1")))
	})

	t.Run("get", func(t *testing.T) {
		_, err := s.Get("k2")
		require.NoError(t, err)
	})

	t.Run("get tags", func(t *testing.T) {
		_, err := s.GetTags("k2")
		require.NoError(t, err)
	})

	t.Run("get tags", func(t *testing.T) {
		_, err := s.GetBulk("k2")
		require.NoError(t, err)
	})

	t.Run("query", func(t *testing.T) {
		_, err := s.Query("q1")
		require.NoError(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		require.NoError(t, s.Delete("k3"))
	})

	t.Run("batch", func(t *testing.T) {
		require.NoError(t, s.Batch(nil))
	})

	t.Run("flush", func(t *testing.T) {
		require.NoError(t, s.Flush())
	})

	t.Run("close", func(t *testing.T) {
		require.NoError(t, s.Close())
	})
}

func TestMongoDBStoreWrapper(t *testing.T) {
	ms := &mocks.MongoDBStore{}

	s := NewMongoDBStore(ms)
	require.NotNil(t, s)

	doc := map[string]interface{}{
		"field1": "value1",
	}

	t.Run("PutAsJSON", func(t *testing.T) {
		require.NoError(t, s.PutAsJSON("k1", doc))
	})

	t.Run("BatchAsJSON", func(t *testing.T) {
		require.NoError(t, s.BatchAsJSON([]mongodb.BatchAsJSONOperation{
			{Key: "k1", Value: doc},
		}))
	})

	t.Run("GetAsRawMap", func(t *testing.T) {
		ms.GetAsRawMapReturns(doc, nil)

		value, err := s.GetAsRawMap("k1")
		require.NoError(t, err)
		require.Equal(t, doc, value)
	})

	t.Run("GetBulkAsRawMap", func(t *testing.T) {
		ms.GetBulkAsRawMapReturns([]map[string]interface{}{doc}, nil)

		value, err := s.GetBulkAsRawMap("k1")
		require.NoError(t, err)
		require.Len(t, value, 1)
		require.Equal(t, doc, value[0])
	})

	t.Run("QueryCustom", func(t *testing.T) {
		mit := &mocks.MongoDBIterator{}
		mit.NextReturns(true, nil)
		mit.ValueAsRawMapReturns(doc, nil)

		ms.QueryCustomReturns(mit, nil)

		it, err := s.QueryCustom("k1")
		require.NoError(t, err)
		require.NotNil(t, it)
	})

	t.Run("CreateMongoDBFindOptions", func(t *testing.T) {
		ms.CreateMongoDBFindOptionsReturns(&options.FindOptions{})

		mongoOpts := s.CreateMongoDBFindOptions([]storage.QueryOption{
			storage.WithPageSize(1000),
		})
		require.NotNil(t, mongoOpts)
	})
}
