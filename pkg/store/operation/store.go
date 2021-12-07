/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	namespace = "operation"
	index     = "suffix"
)

var logger = log.New("operation-store")

// New creates new operation store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open operation store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{index}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{
		store: store,
	}, nil
}

// Store is db implementation of operation store.
type Store struct {
	store storage.Store
}

// Put saves document operations into operation store.
func (s *Store) Put(ops []*operation.AnchoredOperation) error {
	operations := make([]storage.Operation, len(ops))

	putOptions := &storage.PutOptions{IsNewKey: true}

	for i, op := range ops {
		value, err := json.Marshal(op)
		if err != nil {
			return fmt.Errorf("failed to marshal operation: %w", err)
		}

		logger.Debugf("adding operation to storage batch: type[%s], suffix[%s], txtime[%d], pg[%d], buffer: %s",
			op.Type, op.UniqueSuffix, op.TransactionTime, op.ProtocolVersion, string(op.OperationRequest))

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: value,
			Tags: []storage.Tag{
				{
					Name:  index,
					Value: op.UniqueSuffix,
				},
			},
			PutOptions: putOptions,
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store operations: %w", err))
	}

	logger.Debugf("stored %d operations", len(ops))

	return nil
}

// Get retrieves document operations for the given suffix.
func (s *Store) Get(suffix string) ([]*operation.AnchoredOperation, error) {
	var err error

	query := fmt.Sprintf("%s:%s", index, suffix)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get operations for[%s]: %w", query, err))
	}

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("iterator error for suffix[%s] : %w", suffix, err))
	}

	var ops []*operation.AnchoredOperation

	for ok {
		var value []byte

		value, err = iter.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get iterator value for suffix[%s]: %w",
				suffix, err))
		}

		var op operation.AnchoredOperation

		err = json.Unmarshal(value, &op)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal anchored operation from store value for suffix[%s]: %w",
				suffix, err)
		}

		ops = append(ops, &op)

		ok, err = iter.Next()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("iterator error for suffix[%s] : %w", suffix, err))
		}
	}

	logger.Debugf("retrieved %d operations for suffix[%s]", len(ops), suffix)

	if len(ops) == 0 {
		return nil, fmt.Errorf("suffix[%s] not found in the store", suffix)
	}

	return ops, nil
}
