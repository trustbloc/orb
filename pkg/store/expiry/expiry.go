/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package expiry

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	loggerModule          = "expiry-service"
	coordinationPermitKey = "expired_data_cleanup_permit"
	// When the Orb server with the expired data cleanup duty (permit holder) has not done it for an unusually
	// long time (indicating it's down), another Orb server will take over the duty. This value multiplied by the
	// configured interval time defines what an "unusually long time" is.
	permitTimeLimitIntervalMultiplier = 3
)

type logger interface {
	Debugf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
}

type registeredStore struct {
	store storage.Store
	name  string

	expiryTagName string
	expiryHandler expiryHandler
}

// Option is an option for registered store.
type Option func(opts *registeredStore)

// WithExpiryHandler sets optional expiry handler.
func WithExpiryHandler(handler expiryHandler) Option {
	return func(opts *registeredStore) {
		opts.expiryHandler = handler
	}
}

type expiryHandler interface {
	HandleExpiredKeys(keys ...string) error
}

// expiredDataCleanupPermit is used as an entry within the coordination store to ensure that only one Orb instance
// within a cluster has the duty of performing periodic expired data clean up.
type expiredDataCleanupPermit struct {
	// CurrentHolder indicates which Orb server currently has the responsibility.
	CurrentHolder string `json:"currentHolder,omitempty"`
	// TimeLastCleanupPerformed indicates when the last cleanup was successfully performed.
	TimeLastCleanupPerformed int64 `json:"timeCleanupLastPerformed,omitempty"` // This is a Unix timestamp.
}

// Service is an expiry service that periodically polls registered stores and removes data past a specified
// expiration time.
type Service struct {
	*lifecycle.Lifecycle

	done              chan struct{}
	logger            logger
	registeredStores  []registeredStore
	interval          time.Duration
	coordinationStore storage.Store
	instanceID        string
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
func NewService(interval time.Duration, coordinationStore storage.Store, instanceID string) *Service {
	s := &Service{
		done:              make(chan struct{}),
		logger:            log.New(loggerModule),
		registeredStores:  make([]registeredStore, 0),
		interval:          interval,
		coordinationStore: coordinationStore,
		instanceID:        instanceID,
	}

	s.Lifecycle = lifecycle.New("expiry",
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop))

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
		expiryHandler: &noopExpiryHandler{},
	}

	// apply options
	for _, opt := range opts {
		opt(&newRegisteredStore)
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
			s.runExpiryCheck()
		case <-s.done:
			s.logger.Debugf("Stopping expiry service.")

			return
		}
	}
}

func (s *Service) runExpiryCheck() {
	s.logger.Debugf("Checking to see if it's my duty to clean up expired data.")

	if s.isMyDutyToCheckForExpiredData() {
		s.deleteExpiredData()

		err := s.updatePermit()
		if err != nil {
			s.logger.Errorf("Failed to update permit: %s", err.Error())
		}
	}
}

func (s *Service) isMyDutyToCheckForExpiredData() bool {
	currentExpiryCheckPermitBytes, err := s.coordinationStore.Get(coordinationPermitKey)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			s.logger.Infof("No existing permit found. " +
				"I will take on the duty of periodically deleting expired data.")

			return true
		}

		s.logger.Errorf("Unexpected failure while getting the permit: %s", err.Error())

		return false
	}

	var currentPermit expiredDataCleanupPermit

	err = json.Unmarshal(currentExpiryCheckPermitBytes, &currentPermit)
	if err != nil {
		s.logger.Errorf("Failed to unmarshal the current permit: %s", err.Error())

		return false
	}

	timeOfLastCleanup := time.Unix(currentPermit.TimeLastCleanupPerformed, 0)

	// Time.Since uses Time.Now() to determine the current time to a fine degree of precision. Here we are checking the
	// time since a specific Unix timestamp, which is a value that is effectively truncated to the nearest second.
	// Thus, the result of this calculation should also be truncated down to the nearest second since that's all the
	// precision we have. This also makes the log statements look cleaner since it won't display an excessive amount
	// of (meaningless) precision.
	timeSinceLastCleanup := time.Since(timeOfLastCleanup).Truncate(time.Second)

	if currentPermit.CurrentHolder == s.instanceID {
		s.logger.Debugf("It's currently my duty to clean up expired data. I last did this %s ago. I will "+
			"perform another cleanup and then update the permit timestamp.", timeSinceLastCleanup.String())

		return true
	}

	// The idea here is to only take away the data cleanup responsibilities from the current permit holder if it's
	// been an unusually long time since the current permit holder has performed a successful cleanup. If that happens
	// then it indicates that the other Orb server with the permit is down, so someone else needs to grab the permit
	// and take over the duty of doing expired data checks. Note that the assumption here is that all Orb servers
	// within the cluster have the same interval setting (which they should).
	timeLimit := s.interval * permitTimeLimitIntervalMultiplier

	if timeSinceLastCleanup > timeLimit {
		s.logger.Infof("The current permit holder (%s) has not performed an expired data cleanup in an "+
			"unusually long time (%s ago, over %d times longer than the configured interval of %s). This indicates "+
			"that %s may be down or not responding. I will take over the expired data "+
			"cleanup duty and grab the permit.", currentPermit.CurrentHolder, timeSinceLastCleanup.String(),
			permitTimeLimitIntervalMultiplier, s.interval.String(), currentPermit.CurrentHolder)

		return true
	}

	s.logger.Debugf("I will not do an expired data cleanup since %s currently has the duty and did it recently "+
		"(%s ago).", currentPermit.CurrentHolder, timeSinceLastCleanup.String())

	return false
}

func (s *Service) deleteExpiredData() {
	for _, registeredStore := range s.registeredStores {
		registeredStore.deleteExpiredData(s.logger)
	}
}

func (s *Service) updatePermit() error {
	s.logger.Debugf("Updating the permit with the current time.")

	permit := expiredDataCleanupPermit{
		CurrentHolder:            s.instanceID,
		TimeLastCleanupPerformed: time.Now().Unix(),
	}

	permitBytes, err := json.Marshal(permit)
	if err != nil {
		return fmt.Errorf("failed to marshal permit: %w", err)
	}

	err = s.coordinationStore.Put(coordinationPermitKey, permitBytes)
	if err != nil {
		return fmt.Errorf("failed to store permit: %w", err)
	}

	s.logger.Debugf("Permit successfully updated with the current time.")

	return nil
}

func (r *registeredStore) deleteExpiredData(logger logger) { //nolint:funlen
	logger.Debugf("Checking for expired data in %s.", r.name)

	iterator, err := r.store.Query(fmt.Sprintf("%s<=%d", r.expiryTagName, time.Now().Unix()))
	if err != nil {
		logger.Errorf("failed to query store for expired data: %s", err.Error())

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

	err = r.expiryHandler.HandleExpiredKeys(keysToDelete...)
	if err != nil {
		logger.Errorf("failed to invoke expiry handler: %s", err.Error())

		return
	}

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

		logger.Debugf("Successfully deleted %d pieces of expired data.", len(operations))
	}
}

type noopExpiryHandler struct{}

func (h *noopExpiryHandler) HandleExpiredKeys(_ ...string) error {
	return nil
}
