/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logentry

import (
	"encoding/base64"
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

	defaultPageSize = 500
)

var logger = log.New("log-entry-store")

// ErrDataNotFound is returned when data is not found.
var ErrDataNotFound = errors.New("data not found")

// Option is an option for log entry store.
type Option func(opts *Store)

// Store is db implementation of log entry store.
type Store struct {
	store storage.Store

	pageSize int
}

// LogEntry consists of index with log and leaf entry.
type LogEntry struct {
	Index     int
	LeafEntry command.LeafEntry
}

// EntryIterator defines the query results iterator for log entry queries.
type EntryIterator interface {
	// TotalItems returns the total number of items as a result of the query.
	TotalItems() (int, error)
	// Next returns the next log entry or an ErrNotFound error if there are no more items.
	Next() (*command.LeafEntry, error)
	// Close closes the iterator.
	Close() error
}

// New creates db implementation of log entries.
func New(provider storage.Provider, opts ...Option) (*Store, error) {
	store, err := provider.OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open log entry store: %w", err)
	}

	logEntryStore := &Store{
		pageSize: defaultPageSize,
		store:    store,
	}

	for _, opt := range opts {
		opt(logEntryStore)
	}

	return logEntryStore, nil
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
			Value: base64.RawURLEncoding.EncodeToString([]byte(logURL)),
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

// GetLogEntries retrieves log entries.
func (s *Store) GetLogEntries(logURL string) (EntryIterator, error) {
	if logURL == "" {
		return nil, errors.New("missing log URL")
	}

	query := fmt.Sprintf("%s:%s", logTagName, base64.RawURLEncoding.EncodeToString([]byte(logURL)))

	iterator, err := s.store.Query(query,
		storage.WithSortOrder(&storage.SortOptions{
			Order:   storage.SortAscending,
			TagName: indexTagName,
		}),
		storage.WithPageSize(s.pageSize))
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to query log entry store: %w", err))
	}

	return &entryIterator{ariesIterator: iterator}, nil
}

type entryIterator struct {
	ariesIterator storage.Iterator
}

func (e *entryIterator) TotalItems() (int, error) {
	return e.ariesIterator.TotalItems()
}

func (e *entryIterator) Next() (*command.LeafEntry, error) {
	exists, err := e.ariesIterator.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to determine if there are more results: %w", err))
	}

	if exists {
		entryBytes, err := e.ariesIterator.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get value: %w", err))
		}

		var entry LogEntry

		err = json.Unmarshal(entryBytes, &entry)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal entry bytes: %w", err)
		}

		return &entry.LeafEntry, nil
	}

	return nil, ErrDataNotFound
}

func (e *entryIterator) Close() error {
	return e.ariesIterator.Close()
}
