/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const nameSpace = "verifiable"

var logger = log.New("verifiable-store")

// New returns new instance of verifiable credentials store.
func New(provider storage.Provider, loader ld.DocumentLoader) (*Store, error) {
	store, err := provider.OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	return &Store{
		documentLoader: loader,
		store:          store,
		marshal:        json.Marshal,
		unmarshal:      json.Unmarshal,
	}, nil
}

// Store implements storage for verifiable credentials.
type Store struct {
	store          storage.Store
	documentLoader ld.DocumentLoader
	marshal        func(v interface{}) ([]byte, error)
	unmarshal      func(data []byte, v interface{}) error
}

// Put saves an anchor event. If it already exists it will be overwritten.
func (s *Store) Put(anchorEvent *vocab.AnchorEventType) error {
	if anchorEvent.Anchors() == nil {
		return fmt.Errorf("failed to save anchor event: Anchors is empty")
	}

	anchorEventBytes, err := s.marshal(anchorEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal anchor event: %w", err)
	}

	logger.Debugf("storing anchor event: %s", string(anchorEventBytes))

	if e := s.store.Put(anchorEvent.Anchors().String(), anchorEventBytes); e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to put anchor event: %w", e))
	}

	return nil
}

// Get retrieves anchor event by id.
func (s *Store) Get(id string) (*vocab.AnchorEventType, error) {
	anchorEventBytes, err := s.store.Get(id)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get anchor event: %w", err))
	}

	anchorEvent := &vocab.AnchorEventType{}

	err = s.unmarshal(anchorEventBytes, &anchorEvent)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor event: %w", err)
	}

	return anchorEvent, nil
}
