/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package expiry

import (
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	storeutil "github.com/trustbloc/orb/pkg/store"
)

const (
	taskName            = "data-expiry"
	defaultMaxBatchSize = 5000
)

var logger = log.New("expiry-service")

type taskManager interface {
	RegisterTask(taskType string, interval time.Duration, handler func())
}

type registeredStore struct {
	store storage.Store
	name  string

	expiryTagName string
	expiryHandler expiryHandler
	maxBatchSize  int
}

// Option is an option for registered store.
type Option func(opts *registeredStore)

// WithExpiryHandler sets optional expiry handler.
func WithExpiryHandler(handler expiryHandler) Option {
	return func(opts *registeredStore) {
		opts.expiryHandler = handler
	}
}

// WithMaxBatchSize sets maximum number of documents to delete in a single batch.
func WithMaxBatchSize(value int) Option {
	return func(opts *registeredStore) {
		opts.maxBatchSize = value
	}
}

type expiryHandler interface {
	HandleExpiredKeys(keys ...string) ([]string, error)
}

// Service is an expiry service that periodically polls registered stores and removes data past a specified
// expiration time.
type Service struct {
	registeredStores []registeredStore
	mutex            sync.RWMutex
}

// NewService returns a new expiry Service.
// interval is how frequently this service will check for (and delete as needed) expired data. Shorter intervals will
// remove expired data sooner at the expense of increased resource usage. Each Orb instance within a cluster should
// have the same interval configured in order for this service to work efficiently.
// coordinationStore is used for ensuring that only one Orb instance within a cluster has the duty of performing
// expired data cleanup (in order to avoid every instance doing the same work, which is wasteful). Every Orb instance
// within the cluster needs to be connected to the same database for it to work correctly. Note that when initializing
// Orb servers (or if the Orb server with the duty goes down) it is possible for multiple Orb instances to briefly
// assign themselves the duty, but only for one round. This will automatically be resolved on
// the next check and only one will end up with the duty from that point on. This situation is not of concern since
// it's safe for two instances to perform the check at the same time.
// instanceID is used in the coordinationStore for determining who currently has the duty of doing the expired data
// cleanup. It must be unique for every Orb instance within the cluster in order for this service to work efficiently.
// You must register each store you want this service to run on using the Register method. Once all your stores are
// registered, call the Start method to start the service.
func NewService(scheduler taskManager, interval time.Duration) *Service {
	s := &Service{}

	scheduler.RegisterTask(taskName, interval, s.deleteExpiredData)

	return s
}

// Register adds a store to this expiry service.
// store is the store on which to periodically cleanup expired data.
// name is used to identify the purpose of this expiry service for logging purposes.
// expiryTagName is the tag name used to store expiry values under. The expiry values must be standard Unix timestamps.
func (s *Service) Register(store storage.Store, expiryTagName, storeName string, opts ...Option) {
	newRegisteredStore := registeredStore{
		store:         store,
		name:          storeName,
		expiryTagName: expiryTagName,
		maxBatchSize:  defaultMaxBatchSize,
		expiryHandler: &noopExpiryHandler{},
	}

	// apply options
	for _, opt := range opts {
		opt(&newRegisteredStore)
	}

	s.mutex.Lock()

	s.registeredStores = append(s.registeredStores, newRegisteredStore)

	s.mutex.Unlock()
}

func (s *Service) deleteExpiredData() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, registeredStore := range s.registeredStores {
		if err := registeredStore.deleteExpiredData(); err != nil {
			logger.Warn("Error deleting expired data", log.WithError(err), logfields.WithStoreName(registeredStore.name))
		}
	}
}

func (r *registeredStore) deleteExpiredData() error {
	more := true

	for more {
		var err error

		if more, err = r.doDeleteExpiredData(); err != nil {
			return err
		}
	}

	return nil
}

func (r *registeredStore) doDeleteExpiredData() (bool, error) {
	logger.Debug("Checking for expired data in store", logfields.WithStoreName(r.name))

	iterator, err := r.store.Query(fmt.Sprintf("%s<=%d", r.expiryTagName, time.Now().Unix()))
	if err != nil {
		return false, fmt.Errorf("query store for expired data: %w", err)
	}

	defer storeutil.CloseIterator(iterator)

	var keysToDelete []string

	more, err := iterator.Next()
	if err != nil {
		return false, fmt.Errorf("get next value from iterator: %w", err)
	}

	if !more {
		return false, nil
	}

	for more {
		key, errKey := iterator.Key()
		if errKey != nil {
			return false, fmt.Errorf("get key from iterator: %w", errKey)
		}

		keysToDelete = append(keysToDelete, key)

		var errNext error

		more, errNext = iterator.Next()
		if errNext != nil {
			return false, fmt.Errorf("get next value from iterator: %w", errNext)
		}

		if len(keysToDelete) >= r.maxBatchSize {
			break
		}
	}

	logger.Debug("Found expired data to delete.", logfields.WithTotal(len(keysToDelete)), logfields.WithStoreName(r.name))

	keysToDelete, err = r.expiryHandler.HandleExpiredKeys(keysToDelete...)
	if err != nil {
		return false, fmt.Errorf("invoke expiry handler: %w", err)
	}

	if len(keysToDelete) == 0 {
		return false, nil
	}

	operations := make([]storage.Operation, len(keysToDelete))

	for i, key := range keysToDelete {
		logger.Debug("Deleting expired data for key", logfields.WithStoreName(r.name), logfields.WithKey(key))

		operations[i] = storage.Operation{Key: key}
	}

	err = r.store.Batch(operations)
	if err != nil {
		return false, fmt.Errorf("delete expired data - NumDocuments: %d: %w", len(operations), err)
	}

	logger.Debug("Successfully deleted expired data.", logfields.WithStoreName(r.name),
		logfields.WithTotal(len(operations)))

	return more, nil
}

type noopExpiryHandler struct{}

func (h *noopExpiryHandler) HandleExpiredKeys(keys ...string) ([]string, error) {
	return keys, nil
}
