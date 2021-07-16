/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

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
	}, nil
}

// Store implements storage for verifiable credentials.
type Store struct {
	store          storage.Store
	documentLoader ld.DocumentLoader
}

// Put saves a verifiable credential. If it it already exists it will be overwritten.
func (s *Store) Put(vc *verifiable.Credential) error {
	if vc.ID == "" {
		return fmt.Errorf("failed to save vc: ID is empty")
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal vc: %w", err)
	}

	logger.Debugf("storing credential: %s", string(vcBytes))

	if e := s.store.Put(vc.ID, vcBytes); e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to put vc: %w", e))
	}

	return nil
}

// Get retrieves verifiable credential by id.
func (s *Store) Get(id string) (*verifiable.Credential, error) {
	vcBytes, err := s.store.Get(id)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get vc: %w", err))
	}

	vc, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return vc, nil
}
