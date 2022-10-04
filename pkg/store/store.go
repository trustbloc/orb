/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongoopts "go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	"github.com/trustbloc/orb/internal/pkg/log"
)

var logger = log.NewStructured("store")

const idField = "_id"

// TagGroup defines a group of tags that may be used to create a compound index.
type TagGroup []string

// Open opens the store for the given namespace and creates the necessary indexes. As an optimization,
// this function uses vendor-specific APIs (for supported databases) in order to optimize performance.
func Open(provider storage.Provider, namespace string, tagGroups ...TagGroup) (storage.Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("open store [%s]: %w", namespace, err)
	}

	s, ok, err := newVendorStore(provider, store, namespace, tagGroups)
	if err != nil {
		return nil, fmt.Errorf("new vendor store: %w", err)
	}

	if !ok {
		// A vendor-specific store was not found. Use the generic API.
		err := provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: uniqueTags(tagGroups)})
		if err != nil {
			return nil, fmt.Errorf("set store configuration for [%s]: %w", namespace, err)
		}

		s = store
	}

	return s, nil
}

// NewTagGroup is a convenience function that returns a TagGroup from the given set of tags.
func NewTagGroup(tags ...string) TagGroup {
	return tags
}

func newVendorStore(provider storage.Provider, store storage.Store,
	namespace string, tagGroups []TagGroup) (storage.Store, bool, error) {
	// Currently, only MongoDB is supported.
	mongoDBProvider, ok := provider.(mongoDBProvider)
	if !ok {
		return nil, false, nil
	}

	logger.Info("Using MongoDB optimized interface", log.WithStoreName(namespace))

	ms := newMongoDBWrapper(namespace, mongoDBProvider, store)

	if err := ms.createIndexes(tagGroups); err != nil {
		return nil, true, fmt.Errorf("create MongoDB indexes: %w", err)
	}

	return ms, true, nil
}

type mongoDBStore interface {
	PutAsJSON(key string, value interface{}) error
	BulkWrite(models []mongo.WriteModel, opts ...*mongoopts.BulkWriteOptions) error
	GetAsRawMap(id string) (map[string]interface{}, error)
	GetBulkAsRawMap(ids ...string) ([]map[string]interface{}, error)
	QueryCustom(filter interface{}, options ...*mongoopts.FindOptions) (mongodb.Iterator, error)
	CreateMongoDBFindOptions(options []storage.QueryOption, isJSONQuery bool) *mongoopts.FindOptions
}

type mongoDBProvider interface {
	CreateCustomIndexes(storeName string, model ...mongo.IndexModel) error
}

type mongoDBWrapper struct {
	namespace string
	provider  mongoDBProvider
	store     storage.Store
	ms        mongoDBStore
	marshal   func(v interface{}) ([]byte, error)
}

func newMongoDBWrapper(namespace string, provider mongoDBProvider, store storage.Store) *mongoDBWrapper {
	ms, ok := store.(mongoDBStore)
	if !ok {
		// If this happens then it's a bug.
		panic(fmt.Errorf("expecting MongoDB provider for [%s]", namespace))
	}

	return &mongoDBWrapper{
		namespace: namespace,
		provider:  provider,
		store:     store,
		ms:        ms,
		marshal:   json.Marshal,
	}
}

func (s *mongoDBWrapper) createIndexes(tags []TagGroup) error {
	if len(tags) == 0 {
		// Nothing to do.
		return nil
	}

	for _, tagGroup := range tags {
		logger.Info("Creating MongoDB indexes", log.WithStoreName(s.namespace),
			zap.Inline(log.NewObjectMarshaller("tags", tagGroup)))

		keys := make(bson.D, len(tagGroup))

		for i, tag := range tagGroup {
			keys[i] = bson.E{Key: tag, Value: 1}
		}

		model := mongo.IndexModel{Keys: keys}

		err := s.provider.CreateCustomIndexes(s.namespace, model)
		if err != nil {
			return fmt.Errorf("create index for [%s]: %w", s.namespace, err)
		}
	}

	return nil
}

// Put persists the given key-value pair. Tags are unused.
func (s *mongoDBWrapper) Put(key string, value []byte, _ ...storage.Tag) error {
	var doc map[string]interface{}

	if err := json.Unmarshal(value, &doc); err != nil {
		return fmt.Errorf("unmarshal document [%s-%s]: %w", s.namespace, key, err)
	}

	if err := s.ms.PutAsJSON(key, doc); err != nil {
		return fmt.Errorf("put as JSON failed [%s-%s]: %w", s.namespace, key, err)
	}

	return nil
}

// Get returns the value for the given key.
func (s *mongoDBWrapper) Get(key string) ([]byte, error) {
	doc, err := s.ms.GetAsRawMap(key)
	if err != nil {
		return nil, fmt.Errorf("get [%s-%s]: %w", s.namespace, key, err)
	}

	delete(doc, idField)

	docBytes, err := s.marshal(doc)
	if err != nil {
		return nil, err
	}

	return docBytes, nil
}

// GetBulk returns the value for the given keys.
func (s *mongoDBWrapper) GetBulk(keys ...string) ([][]byte, error) {
	docs, err := s.ms.GetBulkAsRawMap(keys...)
	if err != nil {
		return nil, fmt.Errorf("get bulk for [%s]: %w", s.namespace, err)
	}

	docsBytes := make([][]byte, len(docs))

	for i, doc := range docs {
		var docBytes []byte

		var e error

		if doc != nil {
			delete(doc, idField)

			docBytes, e = s.marshal(doc)
			if e != nil {
				return nil, e
			}
		}

		docsBytes[i] = docBytes
	}

	return docsBytes, nil
}

// Query searches the database using the given expression and returns an iterator that may
// be used to retrieve the values.
func (s *mongoDBWrapper) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	filter, err := mongodb.PrepareFilter(strings.Split(expression, "&&"), true)
	if err != nil {
		return nil, fmt.Errorf("convert expression [%s] to MongoDB filter: %w", expression, err)
	}

	iterator, err := s.ms.QueryCustom(filter, s.ms.CreateMongoDBFindOptions(options, true))
	if err != nil {
		return nil, fmt.Errorf("query MongoDB store [%s] - expression [%s]: %w",
			s.namespace, expression, err)
	}

	return newMongoDBIteratorWrapper(iterator), nil
}

// Batch performs multiple Put and/or Delete operations in order.
func (s *mongoDBWrapper) Batch(operations []storage.Operation) error {
	writeModels := make([]mongo.WriteModel, len(operations))

	for i, op := range operations {
		if len(op.Value) > 0 {
			var valueAsMap map[string]interface{}

			jsonDecoder := json.NewDecoder(bytes.NewReader(op.Value))
			jsonDecoder.UseNumber()

			err := jsonDecoder.Decode(&valueAsMap)
			if err != nil {
				return err
			}

			valueAsMap["_id"] = op.Key

			if op.PutOptions != nil && op.PutOptions.IsNewKey {
				writeModels[i] = mongo.NewInsertOneModel().SetDocument(valueAsMap)
			} else {
				filter := bson.M{"_id": op.Key}

				writeModels[i] = mongo.NewReplaceOneModel().SetFilter(filter).
					SetReplacement(valueAsMap).
					SetUpsert(true)
			}
		} else {
			writeModels[i] = mongo.NewDeleteOneModel().SetFilter(bson.M{"_id": op.Key})
		}
	}

	if err := s.ms.BulkWrite(writeModels); err != nil {
		return fmt.Errorf("bulk write failed for [%s]: %w", s.namespace, err)
	}

	return nil
}

// GetTags returns the tags for the given key.
func (s *mongoDBWrapper) GetTags(string) ([]storage.Tag, error) {
	panic("not implemented")
}

// Delete deletes the key + value pair (and all tags) associated with key.
func (s *mongoDBWrapper) Delete(key string) error {
	return s.store.Delete(key)
}

// Flush forces any queued up Put and/or Delete operations to execute.
func (s *mongoDBWrapper) Flush() error {
	return s.store.Flush()
}

// Close closes this store object, freeing resources.
func (s *mongoDBWrapper) Close() error {
	return s.store.Close()
}

type mongoDBIteratorWrapper struct {
	mongodb.Iterator
	marshal func(v interface{}) ([]byte, error)
}

func newMongoDBIteratorWrapper(it mongodb.Iterator) *mongoDBIteratorWrapper {
	return &mongoDBIteratorWrapper{
		Iterator: it,
		marshal:  json.Marshal,
	}
}

func (it *mongoDBIteratorWrapper) Value() ([]byte, error) {
	doc, err := it.ValueAsRawMap()
	if err != nil {
		return nil, err
	}

	delete(doc, idField)

	value, err := it.marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}

	return value, nil
}

func uniqueTags(tagGroups []TagGroup) []string {
	var tags []string

	for _, tagGroup := range tagGroups {
		for _, tag := range tagGroup {
			if !contains(tag, tags) {
				tags = append(tags, tag)
			}
		}
	}

	return tags
}

func contains(tag string, tags []string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}

	return false
}
