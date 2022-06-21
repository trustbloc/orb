/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

func TestProviderWrapper(t *testing.T) {
	s := NewProvider(&mockProvider{}, "CouchDB")
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

	t.Run("ping", func(t *testing.T) {
		require.NoError(t, s.Ping())
	})
}

func TestMongoDBProviderWrapper(t *testing.T) {
	mp := &mocks.MongoDBProvider{}

	p := NewMongoDBProvider(mp)
	require.NotNil(t, p)

	t.Run("open store", func(t *testing.T) {
		mp.OpenStoreReturns(&mocks.MongoDBStore{}, nil)

		_, err := p.OpenStore("s1")
		require.NoError(t, err)
	})

	t.Run("open store error", func(t *testing.T) {
		errExpected := errors.New("injected OpenStore error")

		mp.OpenStoreReturns(nil, errExpected)

		_, err := p.OpenStore("s1")
		require.EqualError(t, err, errExpected.Error())
	})

	t.Run("CreateCustomIndex", func(t *testing.T) {
		err := p.CreateCustomIndexes("s1", mongo.IndexModel{})
		require.NoError(t, err)
	})
}

// mockProvider is a mocked implementation of spi.Provider.
type mockProvider struct{}

// OpenStore returns mocked results.
func (p *mockProvider) OpenStore(string) (storage.Store, error) {
	return nil, nil
}

// SetStoreConfig returns mocked results.
func (p *mockProvider) SetStoreConfig(string, storage.StoreConfiguration) error {
	return nil
}

// GetStoreConfig returns mocked results.
func (p *mockProvider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, nil
}

// GetOpenStores returns mocked results.
func (p *mockProvider) GetOpenStores() []storage.Store {
	return nil
}

// Close returns mocked results.
func (p *mockProvider) Close() error {
	return nil
}

// Ping returns mocked results.
func (p *mockProvider) Ping() error {
	return nil
}
