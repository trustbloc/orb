/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/pkg/store"
)

const storeName = "activity-sync"

type syncStore struct {
	store     storage.Store
	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

func newSyncStore(storageProvider storage.Provider) (*syncStore, error) {
	s, err := store.Open(storageProvider, storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open activity-sync store: %w", err)
	}

	return &syncStore{
		store:     s,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

type syncInfo struct {
	Page  string `json:"page"`
	Index int    `json:"index"`
}

func (s *syncStore) GetLastSyncedPage(serviceIRI *url.URL, source activitySource) (*url.URL, int, error) {
	pageBytes, err := s.store.Get(getKey(serviceIRI, source))
	if err != nil {
		return nil, 0, fmt.Errorf("get from DB: %w", err)
	}

	info := &syncInfo{}

	err = s.unmarshal(pageBytes, info)
	if err != nil {
		return nil, 0, fmt.Errorf("unmarshal sync info [%s]: %w", pageBytes, err)
	}

	pageIRI, err := url.Parse(info.Page)
	if err != nil {
		return nil, 0, fmt.Errorf("parse page IRI [%s]: %w", info.Page, err)
	}

	return pageIRI, info.Index, nil
}

func (s *syncStore) PutLastSyncedPage(serviceIRI *url.URL, source activitySource, page *url.URL, index int) error {
	info := &syncInfo{
		Page:  page.String(),
		Index: index,
	}

	infoBytes, err := s.marshal(info)
	if err != nil {
		return fmt.Errorf("marshal sync info of %s at page [%s] and index %d: %w",
			source, info.Page, info.Index, err)
	}

	err = s.store.Put(getKey(serviceIRI, source), infoBytes)
	if err != nil {
		return fmt.Errorf("put to DB [%s]: %w", infoBytes, err)
	}

	return nil
}

func getKey(serviceIRI *url.URL, source activitySource) string {
	return fmt.Sprintf("%s!%s", serviceIRI, source)
}
