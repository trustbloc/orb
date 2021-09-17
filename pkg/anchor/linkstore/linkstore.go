/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkstore

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
)

const (
	storeName = "anchorlink"
	hashTag   = "anchorHash"
)

var logger = log.New("anchorlinkstore")

// New creates a new anchor link store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor link store: %w", err)
	}

	err = provider.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{hashTag}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{
		store:     store,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

// Store is implements an anchor link store.
type Store struct {
	store     storage.Store
	marshal   func(interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// PutLinks stores the given hash links.
func (s *Store) PutLinks(links []*url.URL) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		anchorHash, err := hashlink.GetResourceHashFromHashLink(link.String())
		if err != nil {
			return fmt.Errorf("get hash from hashlink [%s]: %w", link, err)
		}

		linkBytes, err := s.marshal(link.String())
		if err != nil {
			return fmt.Errorf("marshal anchor link [%s]: %w", link, err)
		}

		logger.Debugf("Storing anchor link for hash [%s]: [%s]", anchorHash, linkBytes)

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: linkBytes,
			Tags: []storage.Tag{
				{
					Name:  hashTag,
					Value: anchorHash,
				},
			},
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor links: %w", err))
	}

	return nil
}

// GetLinks returns the links for the given anchor hash.
func (s *Store) GetLinks(anchorHash string) ([]*url.URL, error) {
	logger.Debugf("Retrieving anchor links for hash [%s]...", anchorHash)

	var err error

	query := fmt.Sprintf("%s:%s", hashTag, anchorHash)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get links for anchor [%s] query[%s]: %w",
			anchorHash, query, err))
	}

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s]: %w", anchorHash, err))
	}

	var links []*url.URL

	for ok {
		value, err := iter.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get iterator value for anchor [%s]: %w",
				anchorHash, err))
		}

		var link string

		err = s.unmarshal(value, &link)
		if err != nil {
			return nil, fmt.Errorf("unmarshal link [%s] for anchor [%s]: %w", value, anchorHash, err)
		}

		u, err := url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("parse link [%s] for anchor [%s]: %w", link, anchorHash, err)
		}

		links = append(links, u)

		ok, err = iter.Next()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s]: %w", anchorHash, err))
		}
	}

	logger.Debugf("Returning anchor links for hash [%s]: %s", anchorHash, links)

	return links, nil
}
