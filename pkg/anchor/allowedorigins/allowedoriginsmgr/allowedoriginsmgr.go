/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginsmgr

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("allowed-origins-mgr")

const (
	allowedOriginKeyPrefix = "allowed-origin_"
	allowedOriginTag       = "allowedOrigin"
)

// Manager manages the allowed anchor origins.
type Manager struct {
	store   storage.Store
	marshal func(v interface{}) ([]byte, error)
}

// New creates an allowed anchor origins manager.
func New(store storage.Store, initialList ...*url.URL) (*Manager, error) {
	s := &Manager{
		store:   store,
		marshal: json.Marshal,
	}

	if err := s.Update(initialList, nil); err != nil {
		return nil, fmt.Errorf("update initial anchor origin list: %w", err)
	}

	return s, nil
}

// Update updates the allowed anchor origin list.
func (s *Manager) Update(additions, deletions []*url.URL) error {
	if len(additions) > 0 {
		current, err := s.Get()
		if err != nil {
			return err
		}

		additions = removeDuplicates(current, additions)
	}

	var operations []storage.Operation

	for _, uri := range additions {
		cfg := &config{
			AllowedOrigin: uri.String(),
		}

		value, e := s.marshal(cfg)
		if e != nil {
			return fmt.Errorf("marshal allowed origin config [%s]: %w", uri, e)
		}

		operations = append(operations, storage.Operation{
			Key:   newKey(uri),
			Value: value,
			Tags:  []storage.Tag{{Name: allowedOriginTag}},
		})
	}

	for _, uri := range deletions {
		operations = append(operations, storage.Operation{
			Key: newKey(uri),
		})
	}

	if len(operations) == 0 {
		logger.Debug("No new additions or deletions for allowed origins.")

		return nil
	}

	if err := s.store.Batch(operations); err != nil {
		return orberrors.NewTransientf("batch update: %w", err)
	}

	logger.Info("Successfully updated the allowed anchor origins",
		log.WithURLAdditions(additions...), log.WithURLDeletions(deletions...))

	return nil
}

// Get returns the allowed anchor origins stored in the database.
// (Note: Use function AllowedOrigins for improved performance since results are cached.)
func (s *Manager) Get() ([]*url.URL, error) {
	var allowed []*url.URL

	it, err := s.store.Query("allowedOrigin")
	if err != nil {
		return nil, orberrors.NewTransientf("query allowed origins: %w", err)
	}

	ok, err := it.Next()
	if err != nil {
		return nil, orberrors.NewTransientf("next allowed origin: %w", err)
	}

	for ok {
		value, e := it.Value()
		if e != nil {
			return nil, orberrors.NewTransientf("allowed origin iterator value: %w", e)
		}

		cfg := &config{}

		e = json.Unmarshal(value, cfg)
		if e != nil {
			return nil, fmt.Errorf("unmarshal allowed origin config: %w", e)
		}

		uri, err := url.Parse(cfg.AllowedOrigin)
		if err != nil {
			logger.Warn("Ignoring invalid allowed origin", log.WithURIString(cfg.AllowedOrigin))
		} else {
			allowed = append(allowed, uri)
		}

		ok, e = it.Next()
		if e != nil {
			return nil, orberrors.NewTransientf("allowed origin iterator next: %w", e)
		}
	}

	logger.Debug("Loaded allowed anchor origins", log.WithURIs(allowed...))

	return allowed, nil
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

func contains(arr []*url.URL, uri *url.URL) bool {
	for _, s := range arr {
		if s.String() == uri.String() {
			return true
		}
	}

	return false
}

func newKey(uri *url.URL) string {
	return allowedOriginKeyPrefix + uri.String()
}

type config struct {
	AllowedOrigin string `json:"allowedOrigin"`
}
