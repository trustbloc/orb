/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	mongoopts "go.mongodb.org/mongo-driver/mongo/options"

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

type mongoDBStore interface {
	PutAsJSON(key string, value interface{}) error
	BatchAsJSON(operations []mongodb.BatchAsJSONOperation) error
	GetAsRawMap(id string) (map[string]interface{}, error)
	GetBulkAsRawMap(ids ...string) ([]map[string]interface{}, error)
	QueryCustom(filter interface{}, options ...*mongoopts.FindOptions) (mongodb.Iterator, error)
	CreateMongoDBFindOptions(options []storage.QueryOption) *mongoopts.FindOptions
}

// MongoDBStoreWrapper wraps a MongoDB store.
type MongoDBStoreWrapper struct {
	*StoreWrapper
	ms mongoDBStore
}

// NewMongoDBStore return new MongoDB store wrapper.
func NewMongoDBStore(s storage.Store) *MongoDBStoreWrapper {
	ms, ok := s.(mongoDBStore)
	if !ok {
		panic("storage is not MongoDB")
	}

	return &MongoDBStoreWrapper{
		StoreWrapper: NewStore(s, "MongoDB"),
		ms:           ms,
	}
}

// PutAsJSON stores the given key and value.
func (store *MongoDBStoreWrapper) PutAsJSON(key string, value interface{}) error {
	start := time.Now()
	defer func() { store.m.DBPutTime(store.dbType, time.Since(start)) }()

	return store.ms.PutAsJSON(key, value)
}

// BatchAsJSON is similar to Batch, but values are stored directly in MongoDB documents without wrapping, with
// keys being used in the _id fields. Values must be structs or maps.
func (store *MongoDBStoreWrapper) BatchAsJSON(operations []mongodb.BatchAsJSONOperation) error {
	start := time.Now()
	defer func() { store.m.DBBatchTime(store.dbType, time.Since(start)) }()

	return store.ms.BatchAsJSON(operations)
}

// GetAsRawMap fetches the full MongoDB JSON document stored with the given id (_id field in MongoDB).
// The document is returned as a map (which includes the _id field).
func (store *MongoDBStoreWrapper) GetAsRawMap(id string) (map[string]interface{}, error) {
	start := time.Now()
	defer func() { store.m.DBGetTime(store.dbType, time.Since(start)) }()

	return store.ms.GetAsRawMap(id)
}

// GetBulkAsRawMap fetches the values associated with the given keys and returns the documents (as maps).
func (store *MongoDBStoreWrapper) GetBulkAsRawMap(keys ...string) ([]map[string]interface{}, error) {
	start := time.Now()
	defer func() { store.m.DBGetBulkTime(store.dbType, time.Since(start)) }()

	return store.ms.GetBulkAsRawMap(keys...)
}

// QueryCustom queries for data using the MongoDB find command. The given filter and options are passed directly to the
// driver. Intended for use alongside the Provider.CreateCustomIndex, Store.PutAsJSON, and
// Iterator.ValueAsRawMap methods.
func (store *MongoDBStoreWrapper) QueryCustom(filter interface{},
	options ...*mongoopts.FindOptions) (mongodb.Iterator, error) {
	start := time.Now()
	defer func() { store.m.DBQueryTime(store.dbType, time.Since(start)) }()

	return store.ms.QueryCustom(filter, options...)
}

// CreateMongoDBFindOptions converts the given storage options to MongoDB options.
func (store *MongoDBStoreWrapper) CreateMongoDBFindOptions(options []storage.QueryOption) *mongoopts.FindOptions {
	return store.ms.CreateMongoDBFindOptions(options)
}
