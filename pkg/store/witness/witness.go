/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package witness

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/anchor/proof"
)

const (
	namespace = "witness"
	vcIndex   = "vcID"
)

var logger = log.New("witness-store")

// New creates new anchor credential witness store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor credential witness store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{vcIndex}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{
		store: store,
	}, nil
}

// Store is db implementation of anchor credential witness store.
type Store struct {
	store storage.Store
}

// Put saves witnesses into anchor credential witness store.
func (s *Store) Put(vcID string, witnesses []*proof.WitnessProof) error {
	operations := make([]storage.Operation, len(witnesses))

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	for i, w := range witnesses {
		value, err := json.Marshal(w)
		if err != nil {
			return fmt.Errorf("failed to marshal anchor credential witness: %w", err)
		}

		logger.Debugf("adding witness to storage batch: %s", w.Witness)

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: value,
			Tags: []storage.Tag{
				{
					Name:  vcIndex,
					Value: vcIDEncoded,
				},
			},
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to store witnesses for vcID[%s]: %w", vcID, err)
	}

	logger.Debugf("stored %d witnesses for vcID[%s]", len(witnesses), vcID)

	return nil
}

// Get retrieves witnesses for the given vc id.
func (s *Store) Get(vcID string) ([]*proof.WitnessProof, error) {
	var err error

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	query := fmt.Sprintf("%s:%s", vcIndex, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get witnesses for[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err)
	}

	var witnesses []*proof.WitnessProof

	for ok {
		var value []byte

		value, err = iter.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get iterator value for vcID[%s]: %w", vcID, err)
		}

		var witness proof.WitnessProof

		err = json.Unmarshal(value, &witness)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal anchor credential witness from store value for vcID[%s]: %w",
				vcID, err)
		}

		witnesses = append(witnesses, &witness)

		ok, err = iter.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err)
		}
	}

	logger.Debugf("retrieved %d witnesses for vcID[%s]", len(witnesses), vcID)

	if len(witnesses) == 0 {
		return nil, fmt.Errorf("vcID[%s] not found in the store", vcID)
	}

	return witnesses, nil
}

// AddProof adds proof for anchor credential id and witness.
func (s *Store) AddProof(vcID, witness string, p []byte) error {
	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	query := fmt.Sprintf("%s:%s", vcIndex, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return fmt.Errorf("failed to get witnesses for[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err)
	}

	for ok {
		var value []byte

		value, err = iter.Value()
		if err != nil {
			return fmt.Errorf("failed to get iterator value for vcID[%s]: %w", vcID, err)
		}

		var w proof.WitnessProof

		err = json.Unmarshal(value, &w)
		if err != nil {
			return fmt.Errorf("failed to unmarshal anchor credential witness from store value for vcID[%s]: %w",
				vcID, err)
		}

		if w.Witness == witness {
			key, err := iter.Key()
			if err != nil {
				return fmt.Errorf("failed to get key for anchor credential vcID[%s] and witness[%s]: %w",
					vcID, witness, err)
			}

			w.Proof = p

			err = s.store.Put(key, value, storage.Tag{Name: vcIndex, Value: vcIDEncoded})
			if err != nil {
				return fmt.Errorf("failed to add proof for anchor credential vcID[%s] and witness[%s]: %w",
					vcID, witness, err)
			}

			logger.Debugf("added proof for anchor credential vcID[%s] and witness[%s]: %s", vcID, witness, string(p))

			return nil
		}
	}

	return fmt.Errorf("witness[%s] not found for vcID[%s]", witness, vcID)
}
