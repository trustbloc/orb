/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorlink

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/store"
)

const nameSpace = "anchor-link"

var logger = log.New("anchor-link-store")

// New returns new instance of anchor event store.
func New(p storage.Provider) (*Store, error) {
	s, err := store.Open(p, nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	return &Store{
		store:     s,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

// Store implements storage for anchor event.
type Store struct {
	store     storage.Store
	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// Put saves an anchor event. If it already exists it will be overwritten.
func (s *Store) Put(anchorLink *linkset.Link) error {
	if anchorLink.Anchor() == nil {
		return fmt.Errorf("failed to save anchor link: Anchor is empty")
	}

	anchorLinkBytes, err := s.marshal(anchorLink)
	if err != nil {
		return fmt.Errorf("failed to marshal anchor link: %w", err)
	}

	logger.Debugf("storing anchor link: %s", string(anchorLinkBytes))

	if e := s.store.Put(anchorLink.Anchor().String(), anchorLinkBytes); e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to put anchor link: %w", e))
	}

	return nil
}

// Get retrieves anchor event by id.
func (s *Store) Get(id string) (*linkset.Link, error) {
	anchorLinkBytes, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, orberrors.NewTransient(fmt.Errorf("failed to get anchor link: %w", err))
	}

	anchorLink := &linkset.Link{}

	err = s.unmarshal(anchorLinkBytes, &anchorLink)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor link: %w", err)
	}

	return anchorLink, nil
}

// Delete deletes anchor event by id.
func (s *Store) Delete(id string) error {
	if err := s.store.Delete(id); err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to delete anchor link id[%s]: %w", id, err))
	}

	logger.Debugf("deleted anchor link id[%s]", id)

	return nil
}
