/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/store"
)

const (
	storeName = "anchor-ref"
	hashTag   = "anchorHash"
)

var logger = log.New("anchor-ref-store")

// New creates a new anchor link store.
func New(provider storage.Provider) (*Store, error) {
	s, err := store.Open(provider, storeName,
		store.NewTagGroup(hashTag),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor ref store: %w", err)
	}

	return &Store{
		store:     s,
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

type anchorLinkRef struct {
	AnchorHash string `json:"anchorHash"`
	URL        string `json:"url"`
}

// PutLinks stores the given hash links.
func (s *Store) PutLinks(links []*url.URL) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		anchorHash, err := hashlink.GetResourceHashFromHashLink(link.String())
		if err != nil {
			return fmt.Errorf("get hash from hashlink [%s]: %w", link, err)
		}

		linkBytes, err := s.marshal(&anchorLinkRef{
			AnchorHash: anchorHash,
			URL:        link.String(),
		})
		if err != nil {
			return fmt.Errorf("marshal anchor ref [%s]: %w", link, err)
		}

		logger.Debugf("Storing anchor ref for hash [%s]: [%s]", anchorHash, linkBytes)

		operations[i] = storage.Operation{
			Key:   getID(link),
			Value: linkBytes,
			Tags: []storage.Tag{
				{
					Name:  hashTag,
					Value: anchorHash,
				},
			},
		}
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor refs: %w", err))
	}

	return nil
}

// DeleteLinks deletes the given hash links.
func (s *Store) DeleteLinks(links []*url.URL) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		anchorHash, err := hashlink.GetResourceHashFromHashLink(link.String())
		if err != nil {
			return fmt.Errorf("get hash from hashlink [%s]: %w", link, err)
		}

		linkBytes, err := s.marshal(link.String())
		if err != nil {
			return fmt.Errorf("marshal anchor ref [%s]: %w", link, err)
		}

		logger.Debugf("Deleting anchor ref for hash [%s]: [%s]", anchorHash, linkBytes)

		operations[i] = storage.Operation{
			Key: getID(link),
		}
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("delete anchor refs: %w", err))
	}

	return nil
}

// GetLinks returns the links for the given anchor hash.
func (s *Store) GetLinks(anchorHash string) ([]*url.URL, error) {
	logger.Debugf("Retrieving anchor refs for hash [%s]...", anchorHash)

	var err error

	query := fmt.Sprintf("%s:%s", hashTag, anchorHash)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get refs for anchor [%s] query[%s]: %w",
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

		linkRef := anchorLinkRef{}

		err = s.unmarshal(value, &linkRef)
		if err != nil {
			return nil, fmt.Errorf("unmarshal link [%s] for anchor [%s]: %w", value, anchorHash, err)
		}

		u, err := url.Parse(linkRef.URL)
		if err != nil {
			return nil, fmt.Errorf("parse link [%s] for anchor [%s]: %w", linkRef.URL, anchorHash, err)
		}

		links = append(links, u)

		ok, err = iter.Next()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s]: %w", anchorHash, err))
		}
	}

	logger.Debugf("Returning anchor refs for hash [%s]: %s", anchorHash, links)

	return links, nil
}

func getID(link *url.URL) string {
	return base64.RawStdEncoding.EncodeToString([]byte(link.String()))
}
