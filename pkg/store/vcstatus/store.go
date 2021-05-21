/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatus

import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/anchor/proof"
)

const (
	namespace = "vcstatus"
	index     = "vcID"
)

var logger = log.New("vc-status")

// New creates new vc status store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc-status store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{index}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{
		store: store,
	}, nil
}

// Store is db implementation of vc status store.
type Store struct {
	store storage.Store
}

// AddStatus adds verifiable credential proof collecting status.
func (s *Store) AddStatus(vcID string, status proof.VCStatus) error {
	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	tag := storage.Tag{
		Name:  index,
		Value: vcIDEncoded,
	}

	err := s.store.Put(uuid.New().String(), []byte(status), tag)
	if err != nil {
		return fmt.Errorf("failed to store vcID[%s] status '%s': %w", vcID, status, err)
	}

	logger.Debugf("stored vcID[%s] status '%s'", vcID, status)

	return nil
}

// GetStatus retrieves proof collection status for the given verifiable credential.
func (s *Store) GetStatus(vcID string) (proof.VCStatus, error) {
	var err error

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	query := fmt.Sprintf("%s:%s", index, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return "", fmt.Errorf("failed to get statuses for vcID[%s] query[%s]: %w", vcID, query, err)
	}

	ok, err := iter.Next()
	if err != nil {
		return "", fmt.Errorf("iterator error for vcID[%s] statuses: %w", vcID, err)
	}

	if !ok {
		return "", fmt.Errorf("status not found for vcID: %s", vcID)
	}

	var value []byte

	for ok {
		value, err = iter.Value()
		if err != nil {
			return "", fmt.Errorf("failed to get iterator value for vcID[%s]: %w", vcID, err)
		}

		if proof.VCStatus(value) == proof.VCStatusCompleted {
			return proof.VCStatusCompleted, nil
		}

		ok, err = iter.Next()
		if err != nil {
			return "", fmt.Errorf("iterator error for vcID[%s]: %w", vcID, err)
		}
	}

	status := proof.VCStatus(value)

	logger.Debugf("status for vcID[%s]: %s", vcID, status)

	return status, nil
}
