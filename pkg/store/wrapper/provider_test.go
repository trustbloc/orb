/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
)

func TestProvider(t *testing.T) {
	s := NewProvider(&ariesmockstorage.Provider{}, "CouchDB")
	require.NotNil(t, s)

	t.Run("open store", func(t *testing.T) {
		_, err := s.OpenStore("s1")
		require.NoError(t, err)
	})

	t.Run("get store config", func(t *testing.T) {
		_, err := s.GetStoreConfig("s1")
		require.NoError(t, err)
	})

	t.Run("set store config", func(t *testing.T) {
		require.NoError(t, s.SetStoreConfig("s1", storage.StoreConfiguration{}))
	})

	t.Run("get open stores", func(t *testing.T) {
		require.Nil(t, s.GetOpenStores())
	})

	t.Run("close", func(t *testing.T) {
		require.NoError(t, s.Close())
	})
}
