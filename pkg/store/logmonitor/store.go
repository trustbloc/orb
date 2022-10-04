/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitor

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store"
)

const (
	namespace = "log-monitor"

	statusIndex = "status"
)

type status = string

const (
	statusActive   status = "active"
	statusInactive status = "inactive"
)

var logger = log.New("log-monitor-store")

// New returns new instance of log monitor store.
func New(provider storage.Provider) (*Store, error) {
	s, err := store.Open(provider, namespace,
		store.NewTagGroup(statusIndex),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open log monitor store: %w", err)
	}

	return &Store{
		store:     s,
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
	Log    string                  `json:"logUrl"`
	STH    *command.GetSTHResponse `json:"sthResponse"`
	PubKey []byte                  `json:"pubKey"`

	Status status `json:"status"`
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
				Status: statusActive,
			}
		} else {
			return orberrors.NewTransientf("failed to get log monitor record: %w", err)
		}
	}

	rec.Status = statusActive

	recBytes, err := s.marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal log monitor record: %w", err)
	}

	logger.Debug("Storing log monitor record", log.WithLogMonitor(rec))

	indexTag := storage.Tag{
		Name:  statusIndex,
		Value: statusActive,
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

	rec.Status = statusInactive

	recBytes, err := s.marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to deactivate log[%s] monitor: marshall error: %w", logURL, err)
	}

	logger.Debug("Deactivating log monitor", log.WithURIString(logURL))

	indexTag := storage.Tag{
		Name:  statusIndex,
		Value: statusInactive,
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

	logger.Debug("Updating log monitor record", log.WithLogMonitor(logMonitor))

	indexTag := storage.Tag{
		Name:  statusIndex,
		Value: logMonitor.Status,
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

	logger.Debug("Deleted log monitor", log.WithURIString(logURL))

	return nil
}

// GetActiveLogs retrieves all active log monitors.
func (s *Store) GetActiveLogs() ([]*LogMonitor, error) {
	return s.getLogs(statusActive)
}

// GetInactiveLogs retrieves all inactive log monitors.
func (s *Store) GetInactiveLogs() ([]*LogMonitor, error) {
	return s.getLogs(statusInactive)
}

func (s *Store) getLogs(status status) ([]*LogMonitor, error) {
	query := fmt.Sprintf("%s:%s", statusIndex, status)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get '%s' log monitors, query[%s]: %w", status, query, err)
	}

	ok, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("iterator error for get '%s' log monitors: %w", status, err)
	}

	if !ok {
		return nil, orberrors.ErrContentNotFound
	}

	var logMonitors []*LogMonitor

	for ok {
		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get iterator value for '%s' log monitors: %w", status, err)
		}

		var logMonitor LogMonitor

		err = s.unmarshal(value, &logMonitor)
		if err != nil {
			return nil, fmt.Errorf("unmarshal log monitor: %w", err)
		}

		logMonitors = append(logMonitors, &logMonitor)

		ok, err = iter.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator error for '%s' log monitors: %w", status, err)
		}
	}

	logger.Debug("Returning log monitors with status", log.WithStatus(status),
		log.WithLogMonitors(logMonitors))

	return logMonitors, nil
}
