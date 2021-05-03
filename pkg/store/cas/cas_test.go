/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas_test

import (
	"errors"
	"testing"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/cas"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := cas.New(ariesmemstorage.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to store in underlying storage provider", func(t *testing.T) {
		provider, err := cas.New(&ariesmockstorage.Provider{ErrOpenStore: errors.New("open store error")})
		require.EqualError(t, err, "failed to open store in underlying storage provider: open store error")
		require.Nil(t, provider)
	})
}

func TestProvider_Write_Read(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := cas.New(ariesmemstorage.NewProvider())
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.NoError(t, err)
		require.Equal(t, "QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG", address)

		content, err := provider.Read(address)
		require.NoError(t, err)
		require.Equal(t, "content", string(content))
	})
	t.Run("Fail to put content bytes into underlying storage provider", func(t *testing.T) {
		provider, err := cas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrPut: errors.New("put error"),
			},
		})
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.EqualError(t, err, "failed to put content into underlying storage provider: put error")
		require.Equal(t, "", address)
	})
	t.Run("Fail to get content bytes from underlying storage provider", func(t *testing.T) {
		t.Run("Data not found", func(t *testing.T) {
			provider, err := cas.New(&ariesmockstorage.Provider{
				OpenStoreReturn: &ariesmockstorage.Store{
					ErrGet: ariesstorage.ErrDataNotFound,
				},
			})
			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.Equal(t, err, cas.ErrContentNotFound)
			require.Nil(t, content)
		})
		t.Run("Other error", func(t *testing.T) {
			provider, err := cas.New(&ariesmockstorage.Provider{
				OpenStoreReturn: &ariesmockstorage.Store{
					ErrGet: errors.New("get error"),
				},
			})
			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.EqualError(t, err, "failed to get content from the underlying storage provider: get error")
			require.Nil(t, content)
		})
	})
}
