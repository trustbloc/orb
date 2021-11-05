/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatus

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	namespace = "vcstatus"

	index         = "vcID"
	expiryTagName = "ExpiryTime"

	// adding time in order to avoid possible errors due to differences in server times.
	delta = 5 * time.Minute
)

var logger = log.New("vc-status")

// New creates new vc status store.
func New(provider storage.Provider, expiryService *expiry.Service, maxWitnessDelay time.Duration) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc-status store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{index, expiryTagName}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	expiryService.Register(store, expiryTagName, namespace)

	return &Store{
		store:          store,
		statusLifespan: maxWitnessDelay + delta,

		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

// Store is db implementation of vc status store.
type Store struct {
	store          storage.Store
	statusLifespan time.Duration

	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// AddStatus adds verifiable credential proof collecting status.
func (s *Store) AddStatus(anchorID string, status proof.VCStatus) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	indexTag := storage.Tag{
		Name:  index,
		Value: anchorIDEncoded,
	}

	expiryTag := storage.Tag{
		Name:  expiryTagName,
		Value: fmt.Sprintf("%d", time.Now().Add(s.statusLifespan).Unix()),
	}

	statusBytes, err := s.marshal(status)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	err = s.store.Put(uuid.New().String(), statusBytes, indexTag, expiryTag)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store anchorID[%s] status '%s': %w",
			anchorID, status, err))
	}

	logger.Debugf("stored anchorID[%s] status '%s'", anchorID, status)

	return nil
}

// GetStatus retrieves proof collection status for the given verifiable credential.
func (s *Store) GetStatus(anchorID string) (proof.VCStatus, error) {
	var err error

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf("%s:%s", index, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("failed to get statuses for anchor event[%s] query[%s]: %w",
			anchorID, query, err))
	}

	ok, err := iter.Next()
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s] statuses: %w", anchorID, err))
	}

	if !ok {
		return "", fmt.Errorf("status not found for anchor event[%s]", anchorID)
	}

	var status proof.VCStatus

	for ok {
		value, err := iter.Value()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("failed to get iterator value for anchor event[%s]: %w",
				anchorID, err))
		}

		err = s.unmarshal(value, &status)
		if err != nil {
			return "", fmt.Errorf("unmarshal status: %w", err)
		}

		if status == proof.VCStatusCompleted {
			return proof.VCStatusCompleted, nil
		}

		ok, err = iter.Next()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s]: %w", anchorID, err))
		}
	}

	logger.Debugf("status for anchor event[%s]: %s", anchorID, status)

	return status, nil
}
