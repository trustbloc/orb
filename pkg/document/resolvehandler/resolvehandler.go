/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"

	"github.com/trustbloc/orb/pkg/context/common"
)

var logger = log.New("orb-resolver")

// ErrDocumentNotFound is document not found error.
var ErrDocumentNotFound = fmt.Errorf("document not found")

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	coreResolver dochandler.Resolver
	discovery    discovery
	store        storage.Store
	anchorGraph  common.AnchorGraph
	metrics      metricsProvider

	namespace           string
	unpublishedDIDLabel string
	enableDidDiscovery  bool

	enableCreateDocumentStore bool
}

// did discovery service.
type discovery interface {
	RequestDiscovery(id string) error
}

type metricsProvider interface {
	DocumentResolveTime(duration time.Duration)
}

// Option is an option for resolve handler.
type Option func(opts *ResolveHandler)

// WithEnableDIDDiscovery sets optional did discovery flag.
func WithEnableDIDDiscovery(enable bool) Option {
	return func(opts *ResolveHandler) {
		opts.enableDidDiscovery = enable
	}
}

// WithUnpublishedDIDLabel sets did label.
func WithUnpublishedDIDLabel(label string) Option {
	return func(opts *ResolveHandler) {
		opts.unpublishedDIDLabel = label
	}
}

// WithCreateDocumentStore will enable resolution from 'create' document store in case
// that document is not found in operations store.
func WithCreateDocumentStore(store storage.Store) Option {
	return func(opts *ResolveHandler) {
		opts.store = store
		opts.enableCreateDocumentStore = true
	}
}

// NewResolveHandler returns a new document resolve handler.
func NewResolveHandler(namespace string, resolver dochandler.Resolver, discovery discovery,
	anchorGraph common.AnchorGraph, metrics metricsProvider, opts ...Option) *ResolveHandler {
	rh := &ResolveHandler{
		namespace:    namespace,
		coreResolver: resolver,
		discovery:    discovery,
		anchorGraph:  anchorGraph,
		metrics:      metrics,
	}

	// apply options
	for _, opt := range opts {
		opt(rh)
	}

	return rh
}

// ResolveDocument resolves a document.
func (r *ResolveHandler) ResolveDocument(id string) (*document.ResolutionResult, error) { //nolint:gocyclo,cyclop
	startTime := time.Now()

	defer func() {
		r.metrics.DocumentResolveTime(time.Since(startTime))
	}()

	response, err := r.coreResolver.ResolveDocument(id)
	if err != nil { //nolint:nestif
		if strings.Contains(err.Error(), "not found") {
			if strings.Contains(id, r.unpublishedDIDLabel) {
				if r.enableCreateDocumentStore {
					createDocResponse, createDocErr := r.resolveDocumentFromCreateDocumentStore(id)
					if createDocErr != nil {
						// return original error (create document store is just convenience)
						return nil, err
					}

					logger.Debugf("successfully resolved id[%s] from create document store", id)

					return createDocResponse, nil
				}
			} else {
				if r.enableDidDiscovery {
					r.requestDiscovery(id)
				}
			}
		}

		return nil, err
	}

	// document was retrieved from operation store

	if strings.Contains(id, r.unpublishedDIDLabel) && r.enableCreateDocumentStore {
		// delete interim document from create document store
		r.deleteDocumentFromCreateDocumentStore(id)
	}

	if !strings.Contains(id, r.unpublishedDIDLabel) {
		// we have to check if CID belongs to the resolved document
		err = r.verifyCID(id, response)
		if err != nil {
			return nil, err
		}
	}

	return response, nil
}

func (r *ResolveHandler) deleteDocumentFromCreateDocumentStore(id string) {
	deleteErr := r.store.Delete(id)
	if deleteErr != nil {
		logger.Warnf("failed to delete id[%s] from create document store: %s", id, deleteErr.Error())
	} else {
		logger.Debugf("deleted id[%s] from create document store", id)
	}
}

func (r *ResolveHandler) resolveDocumentFromCreateDocumentStore(id string) (*document.ResolutionResult, error) {
	createDocBytes, err := r.store.Get(id)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			logger.Warnf("failed to retrieve id[%s] from create document store: %s", id, err.Error())
		}

		return nil, err
	}

	var rr document.ResolutionResult

	err = json.Unmarshal(createDocBytes, &rr)
	if err != nil {
		logger.Warnf("failed to marshal document id[%s] from create document store: %s", id, err.Error())

		return nil, err
	}

	return &rr, nil
}

func (r *ResolveHandler) requestDiscovery(did string) {
	logger.Infof("requesting discovery for did[%s]", did)

	err := r.discovery.RequestDiscovery(did)
	if err != nil {
		logger.Warnf("error while requesting discovery for did[%s]: %s", did, err.Error())
	}
}

func (r *ResolveHandler) verifyCID(id string, rr *document.ResolutionResult) error {
	value, ok := rr.DocumentMetadata[document.CanonicalIDProperty]
	if !ok {
		// this document has not been published so nothing to verify
		return nil
	}

	canonicalID, ok := value.(string)
	if !ok {
		return fmt.Errorf("unexpected interface '%T' for canonicalId", value)
	}

	resolvedCID, suffix, err := getCIDAndSuffix(canonicalID)
	if err != nil {
		return fmt.Errorf("CID from resolved document: %w", err)
	}

	cidFromID, _, err := getCIDAndSuffix(id)
	if err != nil {
		return fmt.Errorf("CID from ID: %w", err)
	}

	if resolvedCID == cidFromID {
		// CIDs match - nothing to do
		return nil
	}

	logger.Debugf("resolved CID[%s] doesn't match requested CID[%s] in DID[%s] - check anchor graph for requested CID",
		resolvedCID, cidFromID, id)

	return r.verifyCIDExistenceInAnchorGraph(cidFromID, resolvedCID, suffix)
}

func (r *ResolveHandler) verifyCIDExistenceInAnchorGraph(cid, anchorCID, anchorSuffix string) error {
	anchors, err := r.anchorGraph.GetDidAnchors(anchorCID, anchorSuffix)
	if err != nil {
		return err
	}

	for _, anchor := range anchors {
		if strings.Contains(anchor.CID, cid) {
			// if requested CID is an old CID we should return found
			return nil
		}
	}

	logger.Debugf("cid[%s] not found in anchor graph starting from cid[%s] and suffix[%s] - return document not found",
		cid, anchorCID, anchorSuffix)

	// if there is a new CID that the resolver doesn’t know about we should return not found
	return ErrDocumentNotFound
}

func getCIDAndSuffix(id string) (string, string, error) {
	parts := strings.Split(id, docutil.NamespaceDelimiter)

	const minOrbIdentifierParts = 4
	if len(parts) < minOrbIdentifierParts {
		return "", "", fmt.Errorf("invalid number of parts[%d] for Orb identifier", len(parts))
	}

	return parts[len(parts)-2], parts[len(parts)-1], nil
}
