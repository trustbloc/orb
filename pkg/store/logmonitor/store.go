/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/controller/command"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	namespace = "log-monitor"

	activeIndex = "active"
)

var logger = log.New("log-monitor-store")

// New returns new instance of log monitor store.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open log monitor store: %w", err)
	}

	err = provider.SetStoreConfig(namespace, storage.StoreConfiguration{TagNames: []string{activeIndex}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{
		store:     store,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}, nil
}

// Store implements storage for log monitors.
type Store struct {
	store     storage.Store
	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// LogMonitor provides information about log monitor.
type LogMonitor struct {
	Log    string                  `json:"log_url"`
	STH    *command.GetSTHResponse `json:"sth_response"`
	PubKey []byte                  `json:"pub_key"`

	Active bool `json:"active"`
}

// Activate stores a log to be monitored. If it already exists active flag will be set to true.
func (s *Store) Activate(logURL string) error {
	if logURL == "" {
		return fmt.Errorf("failed to activate log monitor: log URL is empty")
	}

	rec, err := s.Get(logURL)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			// create new log monitor
			rec = &LogMonitor{
				Log:    logURL,
				Active: true,
			}
		} else {
			return orberrors.NewTransientf("failed to get log monitor record: %w", err)
		}
	}

	rec.Active = true

	recBytes, err := s.marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal log monitor record: %w", err)
	}

	logger.Debugf("storing log monitor: %s", string(recBytes))

	indexTag := storage.Tag{
		Name:  activeIndex,
		Value: "true",
	}

	if e := s.store.Put(logURL, recBytes, indexTag); e != nil {
		return orberrors.NewTransientf("failed to put log monitor: %w", e)
	}

	return nil
}

// Deactivate flags log monitor as inactive.
func (s *Store) Deactivate(logURL string) error {
	if logURL == "" {
		return fmt.Errorf("failed to deactivate log monitor: log URL is empty")
	}

	rec, err := s.Get(logURL)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			return err
		}

		return orberrors.NewTransientf("failed to deactivate log[%s] monitor: %w", logURL, err)
	}

	rec.Active = false

	recBytes, err := s.marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to deactivate log[%s] monitor: marshall error: %w", logURL, err)
	}

	logger.Debugf("deactivating log monitor: %s", logURL)

	indexTag := storage.Tag{
		Name:  activeIndex,
		Value: "false",
	}

	if e := s.store.Put(logURL, recBytes, indexTag); e != nil {
		return orberrors.NewTransientf("failed to deactivate log[%s] monitor: %w", logURL, e)
	}

	return nil
}

// Get retrieves log monitor.
func (s *Store) Get(logURL string) (*LogMonitor, error) {
	recBytes, err := s.store.Get(logURL)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, orberrors.NewTransientf("failed to get log monitor: %w", err)
	}

	var rec LogMonitor

	err = s.unmarshal(recBytes, &rec)
	if err != nil {
		return nil, fmt.Errorf("unmarshal log monitor: %w", err)
	}

	return &rec, nil
}

// Update updates a log monitor.
func (s *Store) Update(logMonitor *LogMonitor) error {
	if logMonitor == nil {
		return fmt.Errorf("log monitor is empty")
	}

	recBytes, err := s.marshal(logMonitor)
	if err != nil {
		return fmt.Errorf("failed to marshal log monitor record: %w", err)
	}

	logger.Debugf("updating log monitor: %s", string(recBytes))

	indexTag := storage.Tag{
		Name:  activeIndex,
		Value: strconv.FormatBool(logMonitor.Active),
	}

	if e := s.store.Put(logMonitor.Log, recBytes, indexTag); e != nil {
		return fmt.Errorf("failed to store log monitor: %w", e)
	}

	return nil
}

// Delete deletes log monitor.
func (s *Store) Delete(logURL string) error {
	if err := s.store.Delete(logURL); err != nil {
		return fmt.Errorf("failed to delete log[%s] monitor: %w", logURL, err)
	}

	logger.Debugf("deleted log monitor: %s", logURL)

	return nil
}

// GetActiveLogs retrieves all active log monitors.
func (s *Store) GetActiveLogs() ([]*LogMonitor, error) {
	return s.getLogs(true)
}

// GetInactiveLogs retrieves all inactive log monitors.
func (s *Store) GetInactiveLogs() ([]*LogMonitor, error) {
	return s.getLogs(false)
}

func (s *Store) getLogs(active bool) ([]*LogMonitor, error) {
	var err error

	label := "active"
	if !active {
		label = "inactive"
	}

	query := fmt.Sprintf("%s:%t", activeIndex, active)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get '%s' log monitors, query[%s]: %w", label, query, err)
	}

	ok, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("iterator error for get '%s' log monitors: %w", label, err)
	}

	if !ok {
		return nil, orberrors.ErrContentNotFound
	}

	var logMonitors []*LogMonitor

	for ok {
		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get iterator value for '%s' log monitors: %w", label, err)
		}

		var logMonitor LogMonitor

		err = s.unmarshal(value, &logMonitor)
		if err != nil {
			return nil, fmt.Errorf("unmarshal log monitor: %w", err)
		}

		logMonitors = append(logMonitors, &logMonitor)

		ok, err = iter.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator error for '%s' log monitors: %w", label, err)
		}
	}

	logger.Debugf("get '%s' log monitors: %+v", label, logMonitors)

	return logMonitors, nil
}
