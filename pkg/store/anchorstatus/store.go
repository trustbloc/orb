/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorstatus

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	namespace = "anchor-status"

	anchorIDTagName        = "anchorID"
	expiryTimeTagName      = "expiryTime"
	statusTagName          = "status"
	statusCheckTimeTagName = "statusCheckTime"

	// adding time in order to avoid possible errors due to differences in server times.
	delta = 5 * time.Minute

	defaultCheckStatusAfterTimePeriod = 10 * time.Second
)

var logger = log.New("anchor-status")

// Option is an option for registered store.
type Option func(opts *Store)

// WithCheckStatusAfterTime sets optional check status interval.
func WithCheckStatusAfterTime(duration time.Duration) Option {
	return func(opts *Store) {
		opts.checkStatusAfterTimePeriod = duration
	}
}

// WithPolicyHandler sets optional policy handler.
func WithPolicyHandler(ph policyHandler) Option {
	return func(opts *Store) {
		opts.policyHandler = ph
	}
}

type policyHandler interface {
	CheckPolicy(anchorID string) error
}

type noopPolicyHandler struct{}

func (s *noopPolicyHandler) CheckPolicy(_ string) error {
	return nil
}

// New creates new anchor event status store.
func New(provider storage.Provider, expiryService *expiry.Service, maxWitnessDelay time.Duration, opts ...Option) (*Store, error) {
	s, err := store.Open(provider, namespace,
		store.NewTagGroup(anchorIDTagName, statusTagName),
		store.NewTagGroup(expiryTimeTagName),
		store.NewTagGroup(statusTagName, statusCheckTimeTagName),
	)
	if err != nil {
		return nil, err
	}

	expiryService.Register(s, expiryTimeTagName, namespace)

	anchorEventStatusStore := &Store{
		store:          s,
		statusLifespan: maxWitnessDelay + delta,

		policyHandler:              &noopPolicyHandler{},
		checkStatusAfterTimePeriod: defaultCheckStatusAfterTimePeriod,

		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}

	for _, opt := range opts {
		opt(anchorEventStatusStore)
	}

	return anchorEventStatusStore, nil
}

// Store is db implementation of anchor index status store.
type Store struct {
	store          storage.Store
	statusLifespan time.Duration

	policyHandler              policyHandler
	checkStatusAfterTimePeriod time.Duration

	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// AddStatus adds verifiable credential proof collecting status.
func (s *Store) AddStatus(anchorID string, status proof.AnchorIndexStatus) error {
	as, tags := s.getAnchorStatusWithTags(anchorID, status)

	asBytes, err := s.marshal(as)
	if err != nil {
		return fmt.Errorf("marshal anchor status: %w", err)
	}

	if err := s.store.Put(uuid.New().String(), asBytes, tags...); err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store anchorID[%s] status '%s': %w",
			anchorID, status, err))
	}

	if status == proof.AnchorIndexStatusCompleted {
		logger.Info("Anchor has completed processing", logfields.WithAnchorURIString(anchorID))

		delErr := s.deleteInProcessStatus(anchorID)
		if delErr != nil {
			// no need to stop processing for this
			logger.Warn("Failed to delete in-process statuses after receiving complete status",
				log.WithError(delErr))
		}
	}

	logger.Debug("Stored status for anchor", logfields.WithAnchorURIString(anchorID), logfields.WithStatus(string(status)))

	return nil
}

func (s *Store) getAnchorStatusWithTags(anchorID string, status proof.AnchorIndexStatus) (*anchorStatus, []storage.Tag) {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	indexTag := storage.Tag{
		Name:  anchorIDTagName,
		Value: anchorIDEncoded,
	}

	statusTag := storage.Tag{
		Name:  statusTagName,
		Value: string(status),
	}

	expiryTime := time.Now().Add(s.statusLifespan).Unix()

	expiryTag := storage.Tag{
		Name:  expiryTimeTagName,
		Value: fmt.Sprintf("%d", expiryTime),
	}

	var statusCheckTime int64

	tags := []storage.Tag{indexTag, statusTag, expiryTag}

	if status != proof.AnchorIndexStatusCompleted {
		statusCheckTime = time.Now().Add(s.checkStatusAfterTimePeriod).Unix()

		tags = append(tags, storage.Tag{
			Name:  statusCheckTimeTagName,
			Value: fmt.Sprintf("%d", statusCheckTime),
		})
	}

	return &anchorStatus{
		AnchorID:        anchorIDEncoded,
		Status:          status,
		ExpiryTime:      expiryTime,
		StatusCheckTime: statusCheckTime,
	}, tags
}

func (s *Store) deleteInProcessStatus(anchorID string) error { //nolint:cyclop
	var err error

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf("%s:%s&&%s:%s",
		anchorIDTagName, anchorIDEncoded,
		statusTagName, proof.AnchorIndexStatusInProcess,
	)

	iter, err := s.store.Query(query)
	if err != nil {
		return fmt.Errorf("failed to get statuses for anchor[%s] query[%s]: %w",
			anchorID, query, err)
	}

	defer store.CloseIterator(iter)

	ok, err := iter.Next()
	if err != nil {
		return fmt.Errorf("iterator error for anchor event[%s] statuses: %w", anchorID, err)
	}

	if !ok {
		// No in-process anchors.
		return nil
	}

	var keysToDelete []string

	for ok {
		statusBytes, e := iter.Value()
		if e != nil {
			return fmt.Errorf("failed to get status for anchor[%s]: %w", anchorID, e)
		}

		status := &anchorStatus{}

		e = s.unmarshal(statusBytes, status)
		if e != nil {
			return fmt.Errorf("unmarshal anchor status for anchor[%s]: %w", anchorID, e)
		}

		key, e := iter.Key()
		if e != nil {
			return fmt.Errorf("failed to get key from iterator for anchor[%s]: %w", anchorID, e)
		}

		keysToDelete = append(keysToDelete, key)

		ok, e = iter.Next()
		if e != nil {
			return orberrors.NewTransientf("iterator error for anchor event[%s]: %w", anchorID, e)
		}
	}

	if len(keysToDelete) > 0 {
		operations := make([]storage.Operation, len(keysToDelete))

		for i, key := range keysToDelete {
			operations[i] = storage.Operation{Key: key}
		}

		err = s.store.Batch(operations)
		if err != nil {
			return fmt.Errorf("failed to delete in process status for anchor [%s]: %w", anchorID, err)
		}

		logger.Debug("Successfully deleted in-process status data for anchor.",
			logfields.WithTotal(len(operations)), logfields.WithAnchorURIString(anchorID))
	}

	return nil
}

// GetStatus retrieves proof collection status for the given verifiable credential.
func (s *Store) GetStatus(anchorID string) (proof.AnchorIndexStatus, error) {
	var err error

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf("%s:%s", anchorIDTagName, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("failed to get statuses for anchor [%s] query[%s]: %w",
			anchorID, query, err))
	}

	defer store.CloseIterator(iter)

	ok, err := iter.Next()
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s] statuses: %w", anchorID, err))
	}

	if !ok {
		return "", fmt.Errorf("status not found for anchor [%s]: %w", anchorID, orberrors.ErrContentNotFound)
	}

	var status proof.AnchorIndexStatus

	for ok {
		value, err := iter.Value()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("failed to get iterator value for anchor event[%s]: %w",
				anchorID, err))
		}

		var anchrStatus anchorStatus

		err = s.unmarshal(value, &anchrStatus)
		if err != nil {
			return "", fmt.Errorf("unmarshal status: %w", err)
		}

		status = anchrStatus.Status

		if anchrStatus.Status == proof.AnchorIndexStatusCompleted {
			return proof.AnchorIndexStatusCompleted, nil
		}

		ok, err = iter.Next()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s]: %w", anchorID, err))
		}
	}

	logger.Debug("Status for anchor", logfields.WithAnchorEventURIString(anchorID), logfields.WithStatus(string(status)))

	return status, nil
}

// CheckInProcessAnchors will be invoked to check for incomplete (not processed) anchors.
func (s *Store) CheckInProcessAnchors() {
	query := fmt.Sprintf("%s:%s&&%s<=%d", statusTagName, proof.AnchorIndexStatusInProcess,
		statusCheckTimeTagName, time.Now().Unix())

	iterator, e := s.store.Query(query)
	if e != nil {
		logger.Error("Failed to query anchor status store", log.WithError(e))

		return
	}

	defer store.CloseIterator(iterator)

	more, e := iterator.Next()
	if e != nil {
		logger.Error("Failed to get next value from iterator", log.WithError(e))

		return
	}

	for more {
		statusBytes, e := iterator.Value()
		if e != nil {
			logger.Error("Failed to get status from iterator", log.WithError(e))

			continue
		}

		status := &anchorStatus{}

		e = s.unmarshal(statusBytes, status)
		if e != nil {
			logger.Error("Failed to unmarshal status from iterator", log.WithError(e))

			continue
		}

		e = s.processIndex(status.AnchorID)
		if e != nil {
			logger.Error("Failed to process anchor index", log.WithError(e))
		}

		more, e = iterator.Next()
		if e != nil {
			logger.Error("Failed to get next value from iterator", log.WithError(e))

			return
		}
	}
}

func (s *Store) processIndex(encodedAnchorID string) error {
	anchorIDBytes, err := base64.RawURLEncoding.DecodeString(encodedAnchorID)
	if err != nil {
		return fmt.Errorf("failed to decode encoded anchorID[%s]: %w", encodedAnchorID, err)
	}

	anchorID := string(anchorIDBytes)

	logger.Debug("Processing anchor", logfields.WithAnchorURIString(anchorID))

	status, err := s.GetStatus(anchorID)
	if err != nil {
		if !errors.Is(err, orberrors.ErrContentNotFound) {
			return fmt.Errorf("failed to get status for anchorID[%s]: %w", anchorID, err)
		}

		logger.Info("Status not found for anchor. No further processing will be performed for this anchor.",
			logfields.WithAnchorURIString(anchorID))

		return nil
	}

	if status == proof.AnchorIndexStatusCompleted {
		logger.Info("Anchor status is already set to completed. No processing required.",
			logfields.WithAnchorURIString(anchorID))

		// Delete all in-process status records
		err = s.deleteInProcessStatus(anchorID)
		if err != nil {
			logger.Warn("Error deleting in process anchor status", log.WithError(err),
				logfields.WithAnchorURIString(anchorID))
		}

		return nil
	}

	err = s.policyHandler.CheckPolicy(anchorID)
	if err != nil {
		if !errors.Is(err, orberrors.ErrWitnessesNotFound) {
			return fmt.Errorf("failed to re-evaluate policy for anchorID[%s]: %w", anchorID, err)
		}

		logger.Info("No additional witnesses found for anchor. No further processing will be performed for this anchor.",
			logfields.WithAnchorURIString(anchorID), log.WithError(err))

		// Delete all in-process status records
		err = s.deleteInProcessStatus(anchorID)
		if err != nil {
			logger.Warn("Error deleting in process anchor status", log.WithError(err),
				logfields.WithAnchorURIString(anchorID))
		}

		return nil
	}

	logger.Info("Successfully re-evaluated policy for anchor", logfields.WithAnchorURIString(anchorID))

	return nil
}

//nolint:tagliatelle
type anchorStatus struct {
	AnchorID        string                  `json:"anchorID"`
	Status          proof.AnchorIndexStatus `json:"status"`
	ExpiryTime      int64                   `json:"expiryTime"`
	StatusCheckTime int64                   `json:"statusCheckTime"`
}
