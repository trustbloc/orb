/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/pkg/metrics"
)

// StoreWrapper wrap aries store.
type StoreWrapper struct {
	s      storage.Store
	m      metricsProvider
	dbType string
}

type metricsProvider interface {
	DBPutTime(dbType string, duration time.Duration)
	DBGetTime(dbType string, duration time.Duration)
	DBGetTagsTime(dbType string, duration time.Duration)
	DBGetBulkTime(dbType string, duration time.Duration)
	DBQueryTime(dbType string, duration time.Duration)
	DBDeleteTime(dbType string, duration time.Duration)
	DBBatchTime(dbType string, duration time.Duration)
}

// NewStore return new store wrapper.
func NewStore(s storage.Store, dbType string) *StoreWrapper {
	return &StoreWrapper{s: s, m: metrics.Get(), dbType: dbType}
}

// Put data.
func (store *StoreWrapper) Put(key string, value []byte, tags ...storage.Tag) error {
	start := time.Now()
	defer func() { store.m.DBPutTime(store.dbType, time.Since(start)) }()

	return store.s.Put(key, value, tags...)
}

// Get data.
func (store *StoreWrapper) Get(key string) ([]byte, error) {
	start := time.Now()
	defer func() { store.m.DBGetTime(store.dbType, time.Since(start)) }()

	return store.s.Get(key)
}

// GetTags get tags.
func (store *StoreWrapper) GetTags(key string) ([]storage.Tag, error) {
	start := time.Now()
	defer func() { store.m.DBGetTagsTime(store.dbType, time.Since(start)) }()

	return store.s.GetTags(key)
}

// GetBulk get bulk.
func (store *StoreWrapper) GetBulk(keys ...string) ([][]byte, error) {
	start := time.Now()
	defer func() { store.m.DBGetBulkTime(store.dbType, time.Since(start)) }()

	return store.s.GetBulk(keys...)
}

// Query from db.
func (store *StoreWrapper) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	start := time.Now()
	defer func() { store.m.DBQueryTime(store.dbType, time.Since(start)) }()

	return store.s.Query(expression, options...)
}

// Delete data.
func (store *StoreWrapper) Delete(key string) error {
	start := time.Now()
	defer func() { store.m.DBDeleteTime(store.dbType, time.Since(start)) }()

	return store.s.Delete(key)
}

// Batch data.
func (store *StoreWrapper) Batch(operations []storage.Operation) error {
	start := time.Now()
	defer func() { store.m.DBBatchTime(store.dbType, time.Since(start)) }()

	return store.s.Batch(operations)
}

// Flush data.
func (store *StoreWrapper) Flush() error {
	return store.s.Flush()
}

// Close store.
func (store *StoreWrapper) Close() error {
	return store.s.Close()
}
