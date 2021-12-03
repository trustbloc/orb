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
)

const storeName = "activity-sync"

type syncStore struct {
	store     storage.Store
	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

func newSyncStore(storageProvider storage.Provider) (*syncStore, error) {
	store, err := storageProvider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open activity-sync store: %w", err)
	}

	return &syncStore{
		store:     store,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

type syncInfo struct {
	Page  string `json:"page"`
	Index int    `json:"index"`
}

func (s *syncStore) GetLastSyncedPage(serviceIRI *url.URL) (*url.URL, int, error) {
	pageBytes, err := s.store.Get(serviceIRI.String())
	if err != nil {
		return nil, 0, fmt.Errorf("get from DB: %w", err)
	}

	info := &syncInfo{}

	err = s.unmarshal(pageBytes, info)
	if err != nil {
		return nil, 0, fmt.Errorf("unmarshal sybc info [%s]: %w", pageBytes, err)
	}

	pageIRI, err := url.Parse(info.Page)
	if err != nil {
		return nil, 0, fmt.Errorf("parse page IRI [%s]: %w", info.Page, err)
	}

	return pageIRI, info.Index, nil
}

func (s *syncStore) PutLastSyncedPage(serviceIRI, page *url.URL, index int) error {
	info := &syncInfo{
		Page:  page.String(),
		Index: index,
	}

	infoBytes, err := s.marshal(info)
	if err != nil {
		return fmt.Errorf("marshal sync info at page [%s] and index %d: %w", info.Page, info.Index, err)
	}

	err = s.store.Put(serviceIRI.String(), infoBytes)
	if err != nil {
		return fmt.Errorf("put to DB [%s]: %w", infoBytes, err)
	}

	return nil
}
