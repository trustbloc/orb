/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store"
)

const (
	namespace = "operation"
	index     = "uniqueSuffix"
)

var logger = log.NewStructured("operation-store")

type metricsProvider interface {
	PutPublishedOperations(duration time.Duration)
	GetPublishedOperations(duration time.Duration)
}

// New creates new operation store.
func New(provider storage.Provider, metrics metricsProvider) (*Store, error) {
	s, err := store.Open(provider, namespace,
		store.NewTagGroup(index),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open operation store: %w", err)
	}

	return &Store{
		store:   s,
		metrics: metrics,
	}, nil
}

// Store is db implementation of operation store.
type Store struct {
	store   storage.Store
	metrics metricsProvider
}

// Put saves document operations into operation store.
func (s *Store) Put(ops []*operation.AnchoredOperation) error {
	startTime := time.Now()

	defer func() {
		s.metrics.PutPublishedOperations(time.Since(startTime))
	}()

	operations := make([]storage.Operation, len(ops))

	putOptions := &storage.PutOptions{IsNewKey: true}

	for i, op := range ops {
		value, err := json.Marshal(op)
		if err != nil {
			return fmt.Errorf("failed to marshal operation: %w", err)
		}

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

		logger.Debug("Adding operation to storage batch", log.WithOperation(op))

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store operations: %w", err))
	}

	logger.Debug("Stored operations", log.WithOperation(len(ops)))

	return nil
}

// Get retrieves document operations for the given suffix.
func (s *Store) Get(suffix string) ([]*operation.AnchoredOperation, error) {
	startTime := time.Now()

	defer func() {
		s.metrics.GetPublishedOperations(time.Since(startTime))
	}()

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

	logger.Debug("Retrieved operations for suffix", log.WithTotal(len(ops)), log.WithSuffix(suffix))

	if len(ops) == 0 {
		return nil, fmt.Errorf("suffix[%s] not found in the store", suffix)
	}

	return ops, nil
}
