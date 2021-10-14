/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package expiry

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

const loggerModule = "expiry-service"

type logger interface {
	Debugf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
}

type registeredStore struct {
	store         storage.Store
	expiryTagName string
	name          string
}

// Service is an expiry service that periodically polls registered stores and removes data past a specified
//  expiration time.
type Service struct {
	*lifecycle.Lifecycle

	done             chan struct{}
	logger           logger
	registeredStores []registeredStore
	interval         time.Duration
}

// NewService returns a new expiry Service.
// interval is how frequently this service will check for (and delete as needed) expired data. Shorter intervals will
// remove expired data sooner at the expense of increased resource usage.
// You must register each store you want this service to run on using the Register method. Once all your stores are
// registered, call the Start method to start the service.
func NewService(interval time.Duration) *Service {
	s := &Service{
		done:             make(chan struct{}),
		logger:           log.New(loggerModule),
		registeredStores: make([]registeredStore, 0),
		interval:         interval,
	}

	s.Lifecycle = lifecycle.New("expiry",
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop))

	return s
}

// Register adds a store to this expiry service.
// store is the store on which to check for expired data.
// name is used to identify the purpose of this expiry service for logging purposes.
// expiryTagName is the tag name used to store expiry values under. The expiry values must be standard Unix timestamps.
func (s *Service) Register(store storage.Store, expiryTagName, storeName string) {
	newRegisteredStore := registeredStore{
		store:         store,
		expiryTagName: expiryTagName,
		name:          storeName,
	}

	s.registeredStores = append(s.registeredStores, newRegisteredStore)
}

func (s *Service) start() {
	go s.refresh()

	s.logger.Infof("Started expiry service.")
}

func (s *Service) stop() {
	close(s.done)

	s.logger.Infof("Stopped expiry service.")
}

func (s *Service) refresh() {
	for {
		select {
		case <-time.After(s.interval):
			s.logger.Debugf("Checking for expired data...")
			s.deleteExpiredData()
		case <-s.done:
			s.logger.Debugf("Stopping expiry service.")

			return
		}
	}
}

func (s *Service) deleteExpiredData() {
	for _, registeredStore := range s.registeredStores {
		registeredStore.deleteExpiredData(s.logger)
	}
}

func (r *registeredStore) deleteExpiredData(logger logger) {
	queryExpression := fmt.Sprintf("%s<=%d", r.expiryTagName, time.Now().Unix())

	logger.Debugf("About to run the following query in %s: %s", r.name, queryExpression)

	iterator, err := r.store.Query(queryExpression)
	if err != nil {
		logger.Errorf("failed to query store: %s", err.Error())

		return
	}

	var keysToDelete []string

	more, err := iterator.Next()
	if err != nil {
		logger.Errorf("failed to get next value from iterator: %s", err.Error())

		return
	}

	for more {
		key, errKey := iterator.Key()
		if errKey != nil {
			logger.Errorf("failed to get key from iterator: %s", errKey.Error())

			return
		}

		keysToDelete = append(keysToDelete, key)

		var errNext error

		more, errNext = iterator.Next()
		if errNext != nil {
			logger.Errorf("failed to get next value from iterator: %s", errNext.Error())

			return
		}
	}

	logger.Debugf("Found %d pieces of expired data to delete in %s.", len(keysToDelete), r.name)

	if len(keysToDelete) > 0 {
		operations := make([]storage.Operation, len(keysToDelete))

		for i, key := range keysToDelete {
			operations[i] = storage.Operation{Key: key}
		}

		err = r.store.Batch(operations)
		if err != nil {
			logger.Errorf("failed to delete expired data: %s", err.Error())

			return
		}

		logger.Debugf("Successfully deleted %d pieces of expired data", len(operations))
	}
}
