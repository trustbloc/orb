/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchor

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ./../mocks/store.gen.go --fake-name Store github.com/hyperledger/aries-framework-go/spi/storage.Store
//go:generate counterfeiter -o ./../mocks/provider.gen.go --fake-name Provider github.com/hyperledger/aries-framework-go/spi/storage.Provider

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - open store fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, fmt.Errorf("open store error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open did anchor store: open store error")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]string{"suffix-1", "suffix-2"}, "cid")
		require.NoError(t, err)
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.BatchReturns(fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]string{"suffix-1", "suffix-2"}, "cid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]string{"suffix-1", "suffix-2"}, "cid")
		require.NoError(t, err)

		anchors, err := s.Get([]string{"suffix-1", "suffix-2"})
		require.NoError(t, err)
		require.Equal(t, "cid", anchors[0])
		require.Equal(t, "cid", anchors[1])
	})

	t.Run("success - with cid not found case", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]string{"suffix-1"}, "cid")
		require.NoError(t, err)

		anchors, err := s.Get([]string{"suffix-1", "suffix-2"})
		require.NoError(t, err)
		require.Equal(t, "cid", anchors[0])
		require.Equal(t, "", anchors[1])
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.GetBulkReturns(nil, fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		anchors, err := s.Get([]string{"suffix"})
		require.Error(t, err)
		require.Nil(t, anchors)
		require.Contains(t, err.Error(), "batch error")
	})
}
