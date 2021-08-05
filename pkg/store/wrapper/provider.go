/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import "github.com/hyperledger/aries-framework-go/spi/storage"

// ProviderWrapper wrap aries provider.
type ProviderWrapper struct {
	p      storage.Provider
	dbType string
}

// NewProvider return new store provider wrapper.
func NewProvider(p storage.Provider, dbType string) *ProviderWrapper {
	return &ProviderWrapper{p: p, dbType: dbType}
}

// OpenStore open store.
func (prov *ProviderWrapper) OpenStore(name string) (storage.Store, error) {
	s, err := prov.p.OpenStore(name)
	if err != nil {
		return nil, err
	}

	return NewStore(s, prov.dbType), nil
}

// SetStoreConfig set store config.
func (prov *ProviderWrapper) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return prov.p.SetStoreConfig(name, config)
}

// GetStoreConfig get store config.
func (prov *ProviderWrapper) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	return prov.p.GetStoreConfig(name)
}

// GetOpenStores get stores.
func (prov *ProviderWrapper) GetOpenStores() []storage.Store {
	return prov.p.GetOpenStores()
}

// Close provider.
func (prov *ProviderWrapper) Close() error {
	return prov.p.Close()
}
