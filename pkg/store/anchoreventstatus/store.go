/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchoreventstatus

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	namespace = "anchor-event-status"

	index = "anchorID"

	expiryTimeTagName = "ExpiryTime"

	statusTagName          = "Status"
	statusCheckTimeTagName = "StatusCheckTime"

	// adding time in order to avoid possible errors due to differences in server times.
	delta = 5 * time.Minute

	defaultCheckStatusAfterTimePeriod = 10 * time.Second
)

var logger = log.New("anchor-event-status")

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
func New(provider storage.Provider, expiryService *expiry.Service, maxWitnessDelay time.Duration,
	opts ...Option) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc-status store: %w", err)
	}

	err = provider.SetStoreConfig(namespace,
		storage.StoreConfiguration{TagNames: []string{index, expiryTimeTagName, statusTagName, statusCheckTimeTagName}},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	expiryService.Register(store, expiryTimeTagName, namespace)

	anchorEventStatusStore := &Store{
		store:          store,
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
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	indexTag := storage.Tag{
		Name:  index,
		Value: anchorIDEncoded,
	}

	statusTag := storage.Tag{
		Name:  statusTagName,
		Value: string(status),
	}

	expiryTag := storage.Tag{
		Name:  expiryTimeTagName,
		Value: fmt.Sprintf("%d", time.Now().Add(s.statusLifespan).Unix()),
	}

	tags := []storage.Tag{indexTag, statusTag, expiryTag}

	if status != proof.AnchorIndexStatusCompleted {
		statusCheckTime := time.Now().Add(s.checkStatusAfterTimePeriod).Unix()

		logger.Debugf("Setting '%s' tag for anchorID[%s]: %d", statusCheckTimeTagName, anchorID, statusCheckTime)

		tags = append(tags, storage.Tag{
			Name:  statusCheckTimeTagName,
			Value: fmt.Sprintf("%d", statusCheckTime),
		})
	}

	statusBytes, err := s.marshal(status)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	err = s.store.Put(uuid.New().String(), statusBytes, tags...)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store anchorID[%s] status '%s': %w",
			anchorID, status, err))
	}

	if status == proof.AnchorIndexStatusCompleted {
		delErr := s.deleteInProcessStatus(anchorID)
		if delErr != nil {
			// no need to stop processing for this
			logger.Debugf("failed to delete in-process statuses after receiving complete status: %s", err.Error())
		}
	}

	logger.Debugf("stored anchorID[%s] status '%s'", anchorID, status)

	return nil
}

func (s *Store) deleteInProcessStatus(anchorID string) error { //nolint:funlen,gocyclo,cyclop
	var err error

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf("%s:%s", index, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return fmt.Errorf("failed to get statuses for anchor event[%s] query[%s]: %w",
			anchorID, query, err)
	}

	ok, err := iter.Next()
	if err != nil {
		return fmt.Errorf("iterator error for anchor event[%s] statuses: %w", anchorID, err)
	}

	if !ok {
		return fmt.Errorf("in-process status not found for anchor event[%s]", anchorID)
	}

	var keysToDelete []string

	for ok {
		tags, errTags := iter.Tags()
		if errTags != nil {
			return fmt.Errorf("failed to get tags for anchor event[%s]: %w",
				anchorID, errTags)
		}

		for _, tag := range tags {
			if tag.Name == statusTagName && tag.Value == string(proof.AnchorIndexStatusInProcess) {
				key, errKey := iter.Key()
				if errKey != nil {
					return fmt.Errorf("failed to get key from iterator: %w", errKey)
				}

				keysToDelete = append(keysToDelete, key)
			}
		}

		ok, err = iter.Next()
		if err != nil {
			return orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s]: %w", anchorID, err))
		}
	}

	if len(keysToDelete) > 0 {
		operations := make([]storage.Operation, len(keysToDelete))

		for i, key := range keysToDelete {
			operations[i] = storage.Operation{Key: key}
		}

		err = s.store.Batch(operations)
		if err != nil {
			return fmt.Errorf("failed to delete in process status for anchor event[%s]: %w", anchorID, err)
		}

		logger.Debugf("Successfully deleted %d pieces of in-process status data for anchor event[%s].",
			len(operations), anchorID)
	}

	return nil
}

// GetStatus retrieves proof collection status for the given verifiable credential.
func (s *Store) GetStatus(anchorID string) (proof.AnchorIndexStatus, error) {
	var err error

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf("%s:%s", index, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("failed to get statuses for anchor event[%s] query[%s]: %w",
			anchorID, query, err))
	}

	ok, err := iter.Next()
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s] statuses: %w", anchorID, err))
	}

	if !ok {
		return "", fmt.Errorf("status not found for anchor event[%s]", anchorID)
	}

	var status proof.AnchorIndexStatus

	for ok {
		value, err := iter.Value()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("failed to get iterator value for anchor event[%s]: %w",
				anchorID, err))
		}

		err = s.unmarshal(value, &status)
		if err != nil {
			return "", fmt.Errorf("unmarshal status: %w", err)
		}

		if status == proof.AnchorIndexStatusCompleted {
			return proof.AnchorIndexStatusCompleted, nil
		}

		ok, err = iter.Next()
		if err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("iterator error for anchor event[%s]: %w", anchorID, err))
		}
	}

	logger.Debugf("status for anchor event[%s]: %s", anchorID, status)

	return status, nil
}

// CheckInProcessAnchors will be invoked to check for in-complete (not processed) anchors.
func (s *Store) CheckInProcessAnchors() {
	query := fmt.Sprintf("%s<=%d", statusCheckTimeTagName, time.Now().Unix())

	iterator, err := s.store.Query(query)
	if err != nil {
		logger.Errorf("failed to query anchor event status store: %s", err.Error())

		return
	}

	more, err := iterator.Next()
	if err != nil {
		logger.Errorf("failed to get next value from iterator: %s", err.Error())

		return
	}

	for more {
		tags, err := iterator.Tags()
		if err != nil {
			logger.Errorf("failed to get key from iterator: %s", err.Error())

			return
		}

		for _, tag := range tags {
			if tag.Name == index {
				err := s.processIndex(tag.Value)
				if err != nil {
					logger.Errorf("failed to process anchor event index: %s", err.Error())
				}

				break
			}
		}

		var errNext error

		more, errNext = iterator.Next()
		if errNext != nil {
			logger.Errorf("failed to get next value from iterator: %s", errNext.Error())

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

	logger.Debugf("Processing anchor event ID[%s]", anchorID)

	status, err := s.GetStatus(anchorID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchorID[%s]: %w", anchorID, err)
	}

	if status == proof.AnchorIndexStatusCompleted {
		// already completed - nothing to do
		return nil
	}

	err = s.policyHandler.CheckPolicy(anchorID)
	if err != nil {
		return fmt.Errorf("failed to re-evalue policy for anchorID[%s]: %w", anchorID, err)
	}

	logger.Debugf("successfully re-evaluated policy for anchorID[%s]", anchorID)

	return nil
}
