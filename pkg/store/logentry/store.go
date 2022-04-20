/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logentry

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/controller/command"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	nameSpace = "log-entry"

	logTagName   = "Log"
	indexTagName = "Index"
)

var logger = log.New("log-entry-store")

// New creates db implementation of log entries.
func New(provider storage.Provider) (*Store, error) {
	store, err := provider.OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open log entry store: %w", err)
	}

	return &Store{
		store: store,
	}, nil
}

// Store is db implementation of log entry store.
type Store struct {
	store storage.Store
}

// LogEntry consists of index with log and leaf entry.
type LogEntry struct {
	Index     int
	LeafEntry command.LeafEntry
}

// StoreLogEntries stores log entries.
func (s *Store) StoreLogEntries(logURL string, start, end uint64, entries []command.LeafEntry) error {
	if len(entries) == 0 {
		return errors.New("missing log entries")
	}

	if logURL == "" {
		return errors.New("missing log URL")
	}

	if len(entries) != int(end-start+1) {
		return fmt.Errorf("expecting %d log entries, got %d entries", int(end-start+1), len(entries))
	}

	operations := make([]storage.Operation, len(entries))

	for i, entry := range entries {
		index := int(start) + i

		logEntry := &LogEntry{
			Index:     index,
			LeafEntry: entry,
		}

		logEntryBytes, err := json.Marshal(logEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}

		indexTag := storage.Tag{
			Name:  indexTagName,
			Value: strconv.Itoa(index),
		}

		logTag := storage.Tag{
			Name:  logTagName,
			Value: logURL,
		}

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: logEntryBytes,
			Tags:  []storage.Tag{logTag, indexTag},
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to add entries for log: %w", err))
	}

	logger.Debugf("added %d entries for log: %s", len(entries), logURL)

	return nil
}
