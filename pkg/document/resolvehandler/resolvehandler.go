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
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/hashlink"
)

var logger = log.New("orb-resolver")

// ErrDocumentNotFound is document not found error.
var ErrDocumentNotFound = fmt.Errorf("document not found")

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	coreResolver dochandler.Resolver
	store        storage.Store
	anchorGraph  common.AnchorGraph
	metrics      metricsProvider

	discoveryService discoveryService
	remoteResolver   remoteResolver
	endpointClient   endpointClient

	namespace string
	domain    string

	unpublishedDIDLabel string

	enableDidDiscovery               bool
	enableResolutionFromAnchorOrigin bool
	enableCreateDocumentStore        bool

	hl *hashlink.HashLink
}

// did discovery service.
type discoveryService interface {
	RequestDiscovery(id string) error
}

type endpointClient interface {
	GetEndpointFromAnchorOrigin(did string) (*models.Endpoint, error)
}

type remoteResolver interface {
	ResolveDocumentFromResolutionEndpoints(id string, endpoints []string) (*document.ResolutionResult, error)
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

// WithEnableResolutionFromAnchorOrigin sets optional resolution from anchor origin flag.
func WithEnableResolutionFromAnchorOrigin(enable bool) Option {
	return func(opts *ResolveHandler) {
		opts.enableResolutionFromAnchorOrigin = enable
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
func NewResolveHandler(namespace string, resolver dochandler.Resolver, discovery discoveryService,
	domain string, endpointClient endpointClient, remoteResolver remoteResolver,
	anchorGraph common.AnchorGraph, metrics metricsProvider, opts ...Option) *ResolveHandler {
	rh := &ResolveHandler{
		namespace:        namespace,
		coreResolver:     resolver,
		discoveryService: discovery,
		domain:           domain,
		endpointClient:   endpointClient,
		remoteResolver:   remoteResolver,
		anchorGraph:      anchorGraph,
		metrics:          metrics,
		hl:               hashlink.New(),
	}

	// apply options
	for _, opt := range opts {
		opt(rh)
	}

	return rh
}

// ResolveDocument resolves a document.
func (r *ResolveHandler) ResolveDocument(id string) (*document.ResolutionResult, error) {
	startTime := time.Now()

	defer func() {
		r.metrics.DocumentResolveTime(time.Since(startTime))
	}()

	if r.enableResolutionFromAnchorOrigin && !strings.Contains(id, r.unpublishedDIDLabel) {
		anchorOriginResponse, err := r.resolveDocumentFromAnchorOrigin(id)
		if err != nil {
			logger.Debugf("resolving locally since resolve from anchor origin returned an error for id[%s]: %s", id, err.Error())

			return r.resolveDocumentLocally(id)
		}

		logger.Debugf("resolution response from anchor origin for id[%s]: %+v", id, anchorOriginResponse)

		// TODO: Parse anchor origin response and apply unpublished operations (if any) to local response
		// and include unpublished operations in document metadata

		localResponse, err := r.resolveDocumentLocally(id)
		if err != nil {
			return nil, err
		}

		return localResponse, nil
	}

	return r.resolveDocumentLocally(id)
}

func (r *ResolveHandler) resolveDocumentFromAnchorOrigin(id string) (*document.ResolutionResult, error) {
	endpoint, err := r.endpointClient.GetEndpointFromAnchorOrigin(id)
	if err != nil {
		return nil, fmt.Errorf("unable to get endpoint from anchor origin for id[%s]: %w", id, err)
	}

	logger.Debugf("retrieved anchor origin[%s] for id[%s], current domain[%s]", endpoint.AnchorOrigin, id, r.domain)

	if endpoint.AnchorOrigin == r.domain {
		return nil, fmt.Errorf(" anchor origin[%s] equals current domain[%s]", endpoint.AnchorOrigin, r.domain)
	}

	anchorOriginResponse, err := r.remoteResolver.ResolveDocumentFromResolutionEndpoints(id, endpoint.ResolutionEndpoints)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve id[%s] from anchor origin endpoints%s: %w",
			id, endpoint.ResolutionEndpoints, err)
	}

	return anchorOriginResponse, nil
}

func (r *ResolveHandler) resolveDocumentLocally(id string) (*document.ResolutionResult, error) { //nolint:gocyclo,cyclop
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
	suffix, err := util.GetSuffix(id)
	if err != nil {
		logger.Warnf("failed to delete document id[%s] from create document store: %s", id, err.Error())

		return
	}

	deleteErr := r.store.Delete(suffix)
	if deleteErr != nil {
		logger.Warnf("failed to delete id[%s] from create document store: %s", id, deleteErr.Error())
	} else {
		logger.Debugf("deleted id[%s] from create document store", id)
	}
}

func (r *ResolveHandler) resolveDocumentFromCreateDocumentStore(id string) (*document.ResolutionResult, error) {
	suffix, err := util.GetSuffix(id)
	if err != nil {
		logger.Warnf("failed to resolve document id[%s] from create document store: %s", id, err.Error())

		return nil, err
	}

	createDocBytes, err := r.store.Get(suffix)
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

	err := r.discoveryService.RequestDiscovery(did)
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

	resolvedCID, suffix, err := r.getCIDAndSuffix(canonicalID)
	if err != nil {
		return fmt.Errorf("CID from resolved document: %w", err)
	}

	cidFromID, _, err := r.getCIDAndSuffix(id)
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
	anchors, err := r.anchorGraph.GetDidAnchors(hashlink.GetHashLinkFromResourceHash(anchorCID), anchorSuffix)
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

func (r *ResolveHandler) getCIDAndSuffix(id string) (string, string, error) {
	suffix, err := util.GetSuffix(id)
	if err != nil {
		return "", "", err
	}

	parts := strings.Split(id, docutil.NamespaceDelimiter)

	// cid is always second last (an exception is hashlink with metadata)
	cid := parts[len(parts)-2]

	if len(parts) == util.MinOrbIdentifierParts {
		// canonical id
		return cid, suffix, nil
	}

	hlOrHint, err := util.BetweenStrings(id, r.namespace+docutil.NamespaceDelimiter, docutil.NamespaceDelimiter+suffix)
	if err != nil {
		return "", "", fmt.Errorf("failed to get value between namespace and suffix: %w", err)
	}

	if strings.HasPrefix(hlOrHint, hashlink.HLPrefix) {
		hlInfo, err := r.hl.ParseHashLink(hlOrHint)
		if err != nil {
			return "", "", err
		}

		cid = hlInfo.ResourceHash
	}

	logger.Debugf("returning cid[%] and suffix[%] for id[%]", cid, suffix, id)

	return cid, suffix, nil
}
