/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acceptlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("accept_list")

const acceptTypeTag = "acceptType"

// Manager manages reads and updates to accept lists of various types.
type Manager struct {
	store     storage.Store
	unmarshal func(data []byte, v interface{}) error
}

// NewManager returns a new accept list manager.
func NewManager(s storage.Store) *Manager {
	return &Manager{
		store:     s,
		unmarshal: json.Unmarshal,
	}
}

type acceptListCfg struct {
	URI        string `json:"uri"`
	AcceptType string `json:"acceptType"`
}

// Update updates an 'accept list' of the given type with the given additions and deletions.
func (m *Manager) Update(acceptType string, additions, deletions []*url.URL) error {
	current, err := m.Get(acceptType)
	if err != nil {
		return fmt.Errorf("query accept list: %w", err)
	}

	additions = removeDuplicates(current, additions)

	var operations []storage.Operation

	for _, uri := range additions {
		cfg := &acceptListCfg{
			URI:        uri.String(),
			AcceptType: acceptType,
		}

		value, e := json.Marshal(cfg)
		if e != nil {
			return fmt.Errorf("marshal accept list config [%s]: %w", uri, e)
		}

		operations = append(operations, storage.Operation{
			Key:   newKey(acceptType, uri),
			Value: value,
			Tags: []storage.Tag{
				{
					Name:  acceptTypeTag,
					Value: acceptType,
				},
			},
		})
	}

	for _, uri := range deletions {
		operations = append(operations, storage.Operation{
			Key: newKey(acceptType, uri),
		})
	}

	if len(operations) == 0 {
		logger.Debug("No new additions or deletions for type.", logfields.WithAcceptListType(acceptType))

		return nil
	}

	err = m.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("batch update: %w", err))
	}

	logger.Debug("Successfully updated the accept list",
		logfields.WithAcceptListType(acceptType), logfields.WithURLAdditions(additions...),
		logfields.WithURLDeletions(deletions...))

	return nil
}

// Get returns the URIs in the 'accept list' of the given type.
func (m *Manager) Get(acceptType string) ([]*url.URL, error) {
	if acceptType == "" {
		return nil, errors.New("type is required")
	}

	lists, err := m.queryByType(acceptType)
	if err != nil {
		return nil, fmt.Errorf("query by type: %w", err)
	}

	if len(lists) == 0 {
		return nil, nil
	}

	acceptList := lists[0]

	if acceptList.Type != acceptType {
		return nil, fmt.Errorf("expecting result of type [%s] but got type [%s]",
			acceptType, acceptList.Type)
	}

	return acceptList.URL, nil
}

// GetAll returns accept lists for all types.
func (m *Manager) GetAll() ([]*spi.AcceptList, error) {
	return m.queryByType("")
}

func (m *Manager) queryByType(acceptType string) ([]*spi.AcceptList, error) {
	it, err := m.store.Query(queryExpression(acceptType))
	if err != nil {
		return nil, orberrors.NewTransientf("query by type [%s]: %w", acceptType, err)
	}

	acceptListMap := make(map[string]*spi.AcceptList)

	for {
		ok, err := m.next(it, acceptListMap)
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}
	}

	var acceptLists []*spi.AcceptList

	for _, list := range acceptListMap {
		acceptLists = append(acceptLists, list)
	}

	return acceptLists, nil
}

func (m *Manager) next(it storage.Iterator, acceptListMap map[string]*spi.AcceptList) (bool, error) {
	ok, err := it.Next()
	if err != nil {
		return false, orberrors.NewTransientf("query next item: %w", err)
	}

	if !ok {
		return false, nil
	}

	value, err := it.Value()
	if err != nil {
		return false, orberrors.NewTransientf("get value: %w", err)
	}

	cfg := &acceptListCfg{}

	err = m.unmarshal(value, &cfg)
	if err != nil {
		logger.Warn("Error unmarshalling accept-list config. The item will be ignored.", log.WithError(err))

		return true, nil
	}

	uri, err := url.Parse(cfg.URI)
	if err != nil {
		logger.Warn("Invalid target URI. The item will be ignored.", logfields.WithTarget(cfg.URI), log.WithError(err))

		return true, nil
	}

	acceptList, ok := acceptListMap[cfg.AcceptType]
	if !ok {
		acceptList = &spi.AcceptList{
			Type: cfg.AcceptType,
		}

		acceptListMap[cfg.AcceptType] = acceptList
	}

	acceptList.URL = append(acceptList.URL, uri)

	return true, nil
}

func removeDuplicates(current, additions []*url.URL) []*url.URL {
	uriMap := make(map[string]*url.URL)

	for _, uri := range additions {
		if !contains(current, uri) {
			uriMap[uri.String()] = uri
		}
	}

	var list []*url.URL

	for _, uri := range uriMap {
		list = append(list, uri)
	}

	return list
}

func newKey(acceptType string, uri fmt.Stringer) string {
	return fmt.Sprintf("%s-%s-%s", acceptTypeTag, acceptType, uri)
}

func queryExpression(acceptType string) string {
	if acceptType == "" {
		return acceptTypeTag
	}

	return fmt.Sprintf("%s:%s", acceptTypeTag, acceptType)
}

func contains(arr []*url.URL, uri *url.URL) bool {
	for _, s := range arr {
		if s.String() == uri.String() {
			return true
		}
	}

	return false
}
