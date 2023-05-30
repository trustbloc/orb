/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/store"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	storeName     = "anchor-ref"
	hashTag       = "anchorHash"
	statusTag     = "status"
	expiryTimeTag = "expiryTime"

	defaultPendingRecordLifespan = 24 * time.Hour
)

var logger = log.New("anchor-ref-store")

type dataExpiryService interface {
	Register(store storage.Store, expiryTagName, storeName string, opts ...expiry.Option)
}

type options struct {
	pendingRecordLifespan time.Duration
}

// Opt is a link store option.
type Opt func(opts *options)

// WithPendingRecordLifespan sets the lifespan of an anchor reference in PENDING state,
// after which it will be deleted.
func WithPendingRecordLifespan(value time.Duration) Opt {
	return func(opts *options) {
		opts.pendingRecordLifespan = value
	}
}

// New creates a new anchor link store.
func New(provider storage.Provider, expiryService dataExpiryService, opts ...Opt) (*Store, error) {
	options := &options{
		pendingRecordLifespan: defaultPendingRecordLifespan,
	}

	for _, opt := range opts {
		opt(options)
	}

	s, err := store.Open(provider, storeName,
		store.NewTagGroup(hashTag, statusTag),
		store.NewTagGroup(expiryTimeTag),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor ref store: %w", err)
	}

	ls := &Store{
		options:   options,
		store:     s,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}

	expiryService.Register(s, expiryTimeTag, storeName, expiry.WithExpiryHandler(ls))

	return ls, nil
}

// Store is implements an anchor link store.
type Store struct {
	*options

	store     storage.Store
	marshal   func(interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

type anchorStatus = string

const (
	statusProcessed anchorStatus = ""
	statusPending   anchorStatus = "PENDING"
)

type anchorLinkRef struct {
	AnchorHash string `json:"anchorHash"`
	URL        string `json:"url"`
	Status     string `json:"status,omitempty"`
	ExpiryTime int64  `json:"expiryTime,omitempty"`
}

// PutLinks stores the given hash links.
func (s *Store) PutLinks(links []*url.URL) error {
	return s.putLinks(links, statusProcessed)
}

// PutPendingLinks stores the given hash links with the status of PENDING. These links are
// yet to be processed. Once they are processed, their status will be updated to processed.
func (s *Store) PutPendingLinks(links []*url.URL) error {
	return s.putLinks(links, statusPending)
}

func (s *Store) putLinks(links []*url.URL, status anchorStatus) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		anchorHash, err := hashlink.GetResourceHashFromHashLink(link.String())
		if err != nil {
			return fmt.Errorf("get hash from hashlink [%s]: %w", link, err)
		}

		tags := []storage.Tag{
			{
				Name:  hashTag,
				Value: anchorHash,
			},
		}

		var expiryTime int64

		if status == statusPending {
			expiryTime = time.Now().Add(s.pendingRecordLifespan).Unix()

			tags = append(tags,
				storage.Tag{
					Name:  expiryTimeTag,
					Value: fmt.Sprintf("%d", expiryTime),
				},
				storage.Tag{
					Name:  statusTag,
					Value: status,
				},
			)
		}

		linkBytes, err := s.marshal(&anchorLinkRef{
			AnchorHash: anchorHash,
			URL:        link.String(),
			Status:     status,
			ExpiryTime: expiryTime,
		})
		if err != nil {
			return fmt.Errorf("marshal anchor ref [%s]: %w", link, err)
		}

		logger.Debug("Storing anchor link reference", logfields.WithAnchorHash(anchorHash), logfields.WithAnchorURI(link),
			logfields.WithStatus(status))

		operations[i] = storage.Operation{
			Key:   getID(link),
			Value: linkBytes,
			Tags:  tags,
		}
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor refs: %w", err))
	}

	return nil
}

// DeleteLinks deletes the given hash links.
func (s *Store) DeleteLinks(links []*url.URL) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		logger.Debug("Deleting anchor link reference", logfields.WithURI(link))

		operations[i] = storage.Operation{
			Key: getID(link),
		}
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("delete anchor refs: %w", err))
	}

	return nil
}

// DeletePendingLinks deletes the given hash links if they are in PENDING status.
func (s *Store) DeletePendingLinks(links []*url.URL) error {
	operations := make([]storage.Operation, len(links))

	for i, link := range links {
		anchorHash, err := hashlink.GetResourceHashFromHashLink(link.String())
		if err != nil {
			return fmt.Errorf("get hash from hashlink [%s]: %w", link, err)
		}

		pendingLinks, err := s.getLinks(anchorHash, fmt.Sprintf("%s:%s&&%s:%s", hashTag, anchorHash, statusTag, statusPending))
		if err != nil {
			return fmt.Errorf("get pending links [%s]: %w", link, err)
		}

		for _, pendingLink := range pendingLinks {
			if pendingLink.String() != link.String() {
				continue
			}

			logger.Debug("Deleting pending anchor link reference", logfields.WithURI(link))

			operations[i] = storage.Operation{
				Key: getID(link),
			}

			break
		}
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("delete pending anchor link refs: %w", err))
	}

	return nil
}

// GetLinks returns the links for the given anchor hash.
func (s *Store) GetLinks(anchorHash string) ([]*url.URL, error) {
	logger.Debug("Retrieving processed anchor link references for anchor hash",
		logfields.WithAnchorHash(anchorHash))

	return s.getLinks(anchorHash, fmt.Sprintf("%s:%s&&!%s", hashTag, anchorHash, statusTag))
}

// GetProcessedAndPendingLinks returns the links for the given anchor hash, including all pending links.
func (s *Store) GetProcessedAndPendingLinks(anchorHash string) ([]*url.URL, error) {
	logger.Debug("Retrieving processed and pending anchor link references for anchor hash",
		logfields.WithAnchorHash(anchorHash))

	return s.getLinks(anchorHash, fmt.Sprintf("%s:%s", hashTag, anchorHash))
}

func (s *Store) getLinks(anchorHash, query string) ([]*url.URL, error) {
	var err error

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to get refs for anchor [%s] query[%s]: %w",
			anchorHash, query, err))
	}

	defer store.CloseIterator(iter)

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s]: %w", anchorHash, err))
	}

	var links []*url.URL

	for ok {
		value, err := iter.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get iterator value for anchor [%s]: %w",
				anchorHash, err))
		}

		linkRef := anchorLinkRef{}

		err = s.unmarshal(value, &linkRef)
		if err != nil {
			return nil, fmt.Errorf("unmarshal link [%s] for anchor [%s]: %w", value, anchorHash, err)
		}

		u, err := url.Parse(linkRef.URL)
		if err != nil {
			return nil, fmt.Errorf("parse link [%s] for anchor [%s]: %w", linkRef.URL, anchorHash, err)
		}

		links = append(links, u)

		ok, err = iter.Next()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("iterator error for anchor [%s]: %w", anchorHash, err))
		}
	}

	logger.Debug("Returning anchor references for anchor hash", logfields.WithAnchorHash(anchorHash), logfields.WithURIs(links...))

	return links, nil
}

// HandleExpiredKeys is invoked by the data expiration handler.
func (s *Store) HandleExpiredKeys(keys ...string) ([]string, error) {
	var keysToDelete []string

	for _, key := range keys {
		ref, err := s.getLink(key)
		if err != nil {
			logger.Warn("Error getting anchor ref", logfields.WithAnchorHash(key), log.WithError(err))

			return nil, err
		}

		if ref.Status != statusProcessed {
			logger.Info("Anchor reference in PENDING state will be deleted", logfields.WithAnchorHash(key))

			keysToDelete = append(keysToDelete, key)
		} else {
			logger.Info("Anchor reference will not be deleted since it's not in PENDING state", logfields.WithAnchorHash(key))
		}
	}

	return keysToDelete, nil
}

func (s *Store) getLink(key string) (*anchorLinkRef, error) {
	refBytes, err := s.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("load anchorLinkRef: %w", err)
	}

	linkRef := anchorLinkRef{}

	err = s.unmarshal(refBytes, &linkRef)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor link: %w", err)
	}

	return &linkRef, nil
}

func getID(link *url.URL) string {
	return base64.RawStdEncoding.EncodeToString([]byte(link.String()))
}
