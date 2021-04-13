/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchor

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
)

const nameSpace = "didanchor"

var logger = log.New("didanchor-store")

// New creates db implementation of latest did/anchor reference.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open did anchor store: %w", err)
	}

	return &Store{
		store: store,
	}, nil
}

// Store is db implementation of latest did/anchor reference.
type Store struct {
	store storage.Store
}

// Put saves anchor cid for specified suffixes. If suffix already exists, anchor value will be overwritten.
func (s *Store) Put(suffixes []string, cid string) error {
	operations := make([]storage.Operation, len(suffixes))

	for i, suffix := range suffixes {
		op := storage.Operation{
			Key:   suffix,
			Value: []byte(cid),
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to add cid[%s] to suffixes%s: %w", cid, suffixes, err)
	}

	logger.Debugf("updated latest anchor[%s] for suffixes: %s", cid, suffixes)

	return nil
}

// Get retrieves anchors for specified suffixes.
func (s *Store) Get(suffixes []string) ([]string, error) {
	anchorBytes, err := s.store.GetBulk(suffixes...)
	if err != nil {
		return nil, fmt.Errorf("failed to get did anchor reference: %w", err)
	}

	anchors := make([]string, len(suffixes))

	for i, a := range anchorBytes {
		if a == nil {
			anchors[i] = ""
		} else {
			anchors[i] = string(a)
		}
	}

	logger.Debugf("retrieved latest anchors%s for suffixes%s", anchors, suffixes)

	return anchors, nil
}
