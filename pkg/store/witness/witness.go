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
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	namespace   = "witness"
	anchorIndex = "anchorID"
)

var logger = log.New("witness-store")

// New creates new anchor credential witness store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor credential witness store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{anchorIndex}})
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
func (s *Store) Put(anchorID string, witnesses []*proof.WitnessProof) error {
	operations := make([]storage.Operation, len(witnesses))

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	for i, w := range witnesses {
		value, err := json.Marshal(w)
		if err != nil {
			return fmt.Errorf("failed to marshal anchor credential witness: %w", err)
		}

		logger.Debugf("adding %s witness to storage batch: %s", w.Type, w.Witness)

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: value,
			Tags: []storage.Tag{
				{
					Name:  anchorIndex,
					Value: anchorIDEncoded,
				},
			},
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store witnesses for anchorID[%s]: %w", anchorID, err))
	}

	logger.Debugf("stored %d witnesses for anchorID[%s]", len(witnesses), anchorID)

	return nil
}

// Delete deletes all witnesses associated with VC ID.
func (s *Store) Delete(vcID string) error {
	var err error

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))
	query := fmt.Sprintf("%s:%s", anchorIndex, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to get witnesses for[%s]: %w", query, err))
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

	if !ok {
		logger.Debugf("no witnesses to delete for vcID[%s], nothing to do", vcID)

		return nil
	}

	var witnessKeys []string

	for ok {
		var key string

		key, err = iter.Key()
		if err != nil {
			return fmt.Errorf("failed to get iterator value for vcID[%s]: %w", vcID, err)
		}

		witnessKeys = append(witnessKeys, key)

		ok, err = iter.Next()
		if err != nil {
			return fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err)
		}
	}

	operations := make([]storage.Operation, len(witnessKeys))

	for i, k := range witnessKeys {
		operations[i] = storage.Operation{Key: k}
	}

	err = s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to delete witnesses for vcID[%s]: %w", vcID, err))
	}

	logger.Debugf("deleted %d witnesses for vcID[%s]", len(witnessKeys), vcID)

	return nil
}

// Get retrieves witnesses for the given vc id.
func (s *Store) Get(vcID string) ([]*proof.WitnessProof, error) {
	var err error

	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	query := fmt.Sprintf("%s:%s", anchorIndex, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get witnesses for[%s]: %w", query, err))
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err))
	}

	var witnesses []*proof.WitnessProof

	for ok {
		var value []byte

		value, err = iter.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get iterator value for vcID[%s]: %w",
				vcID, err))
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
			return nil, orberrors.NewTransient(fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err))
		}
	}

	logger.Debugf("retrieved %d witnesses for vcID[%s]", len(witnesses), vcID)

	if len(witnesses) == 0 {
		return nil, fmt.Errorf("vcID[%s] not found in the store", vcID)
	}

	return witnesses, nil
}

// AddProof adds proof for anchor credential id and witness.
func (s *Store) AddProof(vcID, witness string, p []byte) error { //nolint:funlen,gocyclo,cyclop
	vcIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(vcID))

	query := fmt.Sprintf("%s:%s", anchorIndex, vcIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to get witnesses for[%s]: %w", query, err))
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

	updatedNo := 0

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
			var key string

			key, err = iter.Key()
			if err != nil {
				return fmt.Errorf("failed to get key for anchor credential vcID[%s] and witness[%s]: %w",
					vcID, witness, err)
			}

			w.Proof = p

			witnessProofBytes, marshalErr := json.Marshal(w)
			if marshalErr != nil {
				return fmt.Errorf("failed to marshal witness[%s] proof for vcID[%s]: %w", w.Witness, vcID, marshalErr)
			}

			err = s.store.Put(key, witnessProofBytes, storage.Tag{Name: anchorIndex, Value: vcIDEncoded})
			if err != nil {
				return orberrors.NewTransient(fmt.Errorf("failed to add proof for anchor credential vcID[%s] and witness[%s]: %w",
					vcID, witness, err))
			}

			updatedNo++

			logger.Debugf("added proof for anchor credential vcID[%s] and witness[%s]: %s", vcID, witness, string(p))
		}

		ok, err = iter.Next()
		if err != nil {
			return fmt.Errorf("iterator error for vcID[%s] : %w", vcID, err)
		}
	}

	if updatedNo == 0 {
		return fmt.Errorf("witness[%s] not found for vcID[%s]", witness, vcID)
	}

	return nil
}
