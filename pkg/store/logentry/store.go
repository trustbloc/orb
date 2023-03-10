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
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vct/pkg/controller/command"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store"
)

const (
	nameSpace = "log-entry"

	logTagName    = "logUrl"
	indexTagName  = "index"
	statusTagName = "status"

	defaultPageSize = 500
)

// EntryStatus defines valid values for log entry status.
type EntryStatus string

const (

	// EntryStatusSuccess defines "success" status.
	EntryStatusSuccess EntryStatus = "success"

	// EntryStatusFailed defines "failed" status.
	EntryStatusFailed EntryStatus = "failed"
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
	Index     int               `json:"index"`
	LeafEntry command.LeafEntry `json:"leafEntry"`
	LogURL    string            `json:"logUrl"`
	Status    EntryStatus       `json:"status"`
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
	s, err := store.Open(provider, nameSpace,
		store.NewTagGroup(logTagName, indexTagName, statusTagName),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open log entry store: %w", err)
	}

	logEntryStore := &Store{
		pageSize: defaultPageSize,
		store:    s,
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
			LogURL:    base64.RawURLEncoding.EncodeToString([]byte(logURL)),
			Status:    EntryStatusSuccess,
		}

		logEntryBytes, err := json.Marshal(logEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}

		indexTag := storage.Tag{
			Name:  indexTagName,
			Value: strconv.Itoa(logEntry.Index),
		}

		statusTag := storage.Tag{
			Name:  statusTagName,
			Value: string(EntryStatusSuccess),
		}

		logTag := storage.Tag{
			Name:  logTagName,
			Value: logEntry.LogURL,
		}

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: logEntryBytes,
			Tags:  []storage.Tag{logTag, indexTag, statusTag},
		}

		operations[i] = op
	}

	if err := s.store.Batch(operations); err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to add entries for log: %w", err))
	}

	logger.Debug("Added entries for log", logfields.WithTotal(len(entries)), logfields.WithLogURLString(logURL))

	return nil
}

// FailLogEntriesFrom updates all log entries from start (until end) and tags them with status=failure.
func (s *Store) FailLogEntriesFrom(logURL string, start uint64) error { //nolint: cyclop
	if logURL == "" {
		return errors.New("missing log URL")
	}

	query := fmt.Sprintf("%s:%s&&%s>=%d&&%s:%s", logTagName, base64.RawURLEncoding.EncodeToString([]byte(logURL)),
		indexTagName, start, statusTagName, EntryStatusSuccess)

	iterator, e := s.store.Query(query,
		storage.WithSortOrder(&storage.SortOptions{
			Order:   storage.SortAscending,
			TagName: indexTagName,
		}),
		storage.WithPageSize(s.pageSize))
	if e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to query log entry store: %w", e))
	}

	ok, e := iterator.Next()
	if e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to determine if there are more results: %w", e))
	}

	if !ok {
		// nothing to do
		return nil
	}

	var operations []storage.Operation

	for ok {
		entryBytes, err := iterator.Value()
		if err != nil {
			return orberrors.NewTransient(fmt.Errorf("failed to get value: %w", err))
		}

		tags, err := iterator.Tags()
		if err != nil {
			return orberrors.NewTransient(fmt.Errorf("failed to get tags: %w", err))
		}

		for i, tag := range tags {
			if tag.Name == statusTagName {
				tags[i].Value = string(EntryStatusFailed)
			}
		}

		key, err := iterator.Key()
		if err != nil {
			return orberrors.NewTransient(fmt.Errorf("failed to get key: %w", err))
		}

		var entry LogEntry

		err = json.Unmarshal(entryBytes, &entry)
		if err != nil {
			return fmt.Errorf("failed to unmarshal entry bytes: %w", err)
		}

		entry.Status = EntryStatusFailed

		entryBytes, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal entry bytes: %w", err)
		}

		op := storage.Operation{
			Key:   key,
			Value: entryBytes,
			Tags:  tags,
		}

		operations = append(operations, op)

		ok, err = iterator.Next()
		if err != nil {
			return orberrors.NewTransient(fmt.Errorf("failed to determine if there are more results: %w", err))
		}
	}

	e = s.store.Batch(operations)
	if e != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to update %d entries to failed for log: %w", len(operations), e))
	}

	logger.Debug("Updated entries to 'failed' for log", logfields.WithTotal(len(operations)), logfields.WithLogURLString(logURL))

	return nil
}

// GetLogEntries retrieves log entries.
func (s *Store) GetLogEntries(logURL string) (EntryIterator, error) {
	if logURL == "" {
		return nil, errors.New("missing log URL")
	}

	query := fmt.Sprintf("%s:%s&&%s:%s", logTagName, base64.RawURLEncoding.EncodeToString([]byte(logURL)),
		statusTagName, EntryStatusSuccess)

	return s.queryEntries(query)
}

// GetFailedLogEntries retrieves failed log entries.
func (s *Store) GetFailedLogEntries(logURL string) (EntryIterator, error) {
	if logURL == "" {
		return nil, errors.New("missing log URL")
	}

	query := fmt.Sprintf("%s:%s&&%s:%s", logTagName, base64.RawURLEncoding.EncodeToString([]byte(logURL)),
		statusTagName, EntryStatusFailed)

	return s.queryEntries(query)
}

// GetLogEntriesFrom retrieves log entries from index start.
func (s *Store) GetLogEntriesFrom(logURL string, start uint64) (EntryIterator, error) {
	if logURL == "" {
		return nil, errors.New("missing log URL")
	}

	query := fmt.Sprintf("%s:%s&&%s>=%d&&%s:%s", logTagName, base64.RawURLEncoding.EncodeToString([]byte(logURL)),
		indexTagName, start, statusTagName, EntryStatusSuccess)

	return s.queryEntries(query)
}

// query entries retrieves log entries.
func (s *Store) queryEntries(query string) (EntryIterator, error) {
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
