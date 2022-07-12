/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchor

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/didanchor"
	orberrors "github.com/trustbloc/orb/pkg/errors"
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

// PutBulk saves anchor cid for specified suffixes. If suffix already exists, anchor value will be overwritten.
func (s *Store) PutBulk(suffixes []string, areNew []bool, cid string) error {
	if len(suffixes) == 0 {
		return errors.New("no suffixes provided")
	}

	operations := make([]storage.Operation, len(suffixes))

	for i, suffix := range suffixes {
		op := storage.Operation{
			Key:        suffix,
			Value:      []byte(cid),
			PutOptions: &storage.PutOptions{IsNewKey: areNew[i]},
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateKey) {
			logger.Warnf("Failed to add cid[%s] to suffixes using the batch speed optimization. "+
				"This can happen if this Orb server is in a recovery flow. Will retry without the "+
				"optimization now (will be slower). Underlying error message: %s", cid, err.Error())

			for i, suffix := range suffixes {
				op := storage.Operation{
					Key:   suffix,
					Value: []byte(cid),
				}

				operations[i] = op
			}

			err = s.store.Batch(operations)
			if err != nil {
				return orberrors.NewTransient(fmt.Errorf("failed to add cid[%s] to suffixes: %w", cid, err))
			}
		} else {
			return orberrors.NewTransient(fmt.Errorf("failed to add cid[%s] to suffixes: %w", cid, err))
		}
	}

	logger.Debugf("updated latest anchor[%s] for suffixes: %s", cid, suffixes)

	return nil
}

// GetBulk retrieves anchors for specified suffixes.
func (s *Store) GetBulk(suffixes []string) ([]string, error) {
	anchorBytes, err := s.store.GetBulk(suffixes...)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get did anchor reference: %w", err))
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

// Get retrieves anchor for specified suffix.
func (s *Store) Get(suffix string) (string, error) {
	anchorBytes, err := s.store.Get(suffix)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return "", didanchor.ErrDataNotFound
		}

		return "", orberrors.NewTransient(fmt.Errorf("failed to get content from the underlying storage provider: %w", err))
	}

	anchor := string(anchorBytes)

	logger.Debugf("retrieved latest anchor[%s] for suffix[%s]", anchor, suffix)

	return anchor, nil
}
