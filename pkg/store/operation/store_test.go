/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ./../mocks/store.gen.go --fake-name Store github.com/hyperledger/aries-framework-go/spi/storage.Store
//go:generate counterfeiter -o ./../mocks/provider.gen.go --fake-name Provider github.com/hyperledger/aries-framework-go/spi/storage.Provider
//go:generate counterfeiter -o ./../mocks/iterator.gen.go --fake-name Iterator github.com/hyperledger/aries-framework-go/spi/storage.Iterator

const testSuffix = "suffix"

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("success - index exists", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.GetStoreConfigReturns(storage.StoreConfiguration{TagNames: []string{index}}, nil)

		s, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("success - different server won in race to create index", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		provider.GetStoreConfigReturnsOnCall(0, storage.StoreConfiguration{}, nil)
		provider.GetStoreConfigReturnsOnCall(1, storage.StoreConfiguration{TagNames: []string{index}}, nil)

		s, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - open store fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, fmt.Errorf("open store error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open operation store: open store error")
		require.Nil(t, s)
	})

	t.Run("error - get store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.GetStoreConfigReturns(storage.StoreConfiguration{}, fmt.Errorf("get store config error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get operation store config: get store config error")
		require.Nil(t, s)
	})

	t.Run("error - set store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		provider.GetStoreConfigReturnsOnCall(0, storage.StoreConfiguration{}, nil)
		provider.GetStoreConfigReturnsOnCall(1, storage.StoreConfiguration{}, nil)

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to set index: set store config error")
		require.Nil(t, s)
	})

	t.Run("error - second get store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		provider.GetStoreConfigReturnsOnCall(0, storage.StoreConfiguration{}, nil)
		provider.GetStoreConfigReturnsOnCall(1, storage.StoreConfiguration{}, fmt.Errorf("get store config error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get operation store config: get store config error")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]*operation.AnchoredOperation{getTestOperation()})
		require.NoError(t, err)
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.BatchReturns(fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]*operation.AnchoredOperation{getTestOperation()})
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.Put([]*operation.AnchoredOperation{getTestOperation()})
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.NoError(t, err)
		require.NotEmpty(t, ops)
	})

	t.Run("success - not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "batch error")
	})

	t.Run("error - iterator next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator value() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(nil, fmt.Errorf("iterator value() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "iterator value() error")
	})

	t.Run("error - unmarshal anchored operation error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns([]byte("not-json"), nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		ops, err := s.Get(testSuffix)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(),
			"failed to unmarshal anchored operation from store value for suffix[suffix]")
	})
}

func getTestOperation() *operation.AnchoredOperation {
	return &operation.AnchoredOperation{
		Type:         operation.TypeCreate,
		UniqueSuffix: testSuffix,
	}
}
