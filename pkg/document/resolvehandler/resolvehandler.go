/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

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
	coreResolver coreResolver
	store        storage.Store
	anchorGraph  common.AnchorGraph
	metrics      metricsProvider

	discoveryService discoveryService
	remoteResolver   remoteResolver
	endpointClient   endpointClient

	namespace string
	domain    string

	unpublishedDIDLabel string

	enableDidDiscovery bool

	enableResolutionFromAnchorOrigin bool

	enableCreateDocumentStore bool

	hl *hashlink.HashLink
}

// Resolver resolves documents.
type coreResolver interface {
	ResolveDocument(idOrDocument string, additionalOps ...*operation.AnchoredOperation) (*document.ResolutionResult, error)
}

// did discovery service.
type discoveryService interface {
	RequestDiscovery(id string) error
}

type endpointClient interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
}

type remoteResolver interface {
	ResolveDocumentFromResolutionEndpoints(id string, endpoints []string) (*document.ResolutionResult, error)
}

type metricsProvider interface {
	DocumentResolveTime(duration time.Duration)
	ResolveDocumentLocallyTime(duration time.Duration)
	GetAnchorOriginEndpointTime(duration time.Duration)
	ResolveDocumentFromAnchorOriginTime(duration time.Duration)
	DeleteDocumentFromCreateDocumentStoreTime(duration time.Duration)
	ResolveDocumentFromCreateDocumentStoreTime(duration time.Duration)
	VerifyCIDTime(duration time.Duration)
	RequestDiscoveryTime(duration time.Duration)
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
func NewResolveHandler(namespace string, resolver coreResolver, discovery discoveryService,
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

	localResponse, err := r.resolveDocumentLocally(id)
	if err != nil {
		return nil, err
	}

	if r.enableResolutionFromAnchorOrigin && !strings.Contains(id, r.unpublishedDIDLabel) {
		return r.resolveDocumentFromAnchorOriginAndCombineWithLocal(id, localResponse)
	}

	return localResponse, nil
}

func (r *ResolveHandler) resolveDocumentFromAnchorOriginAndCombineWithLocal(id string, localResponse *document.ResolutionResult) (*document.ResolutionResult, error) { //nolint:lll,funlen
	localAnchorOrigin, err := util.GetAnchorOrigin(localResponse.DocumentMetadata)
	if err != nil {
		logger.Debugf("resolving locally since there was an error while getting anchor origin from local response[%s]: %s", id, err.Error()) //nolint:lll

		// this error should never happen - return local response
		return localResponse, nil
	}

	if localAnchorOrigin == r.domain {
		// nothing to do since DID's anchor origin equals current domain - return local response
		return localResponse, nil
	}

	anchorOriginResponse, err := r.resolveDocumentFromAnchorOrigin(id, localAnchorOrigin)
	if err != nil {
		logger.Debugf("resolving locally since there was an error while getting local anchor origin for id[%s]: %s",
			id, err.Error()) //

		return localResponse, nil
	}

	logger.Debugf("resolution response from anchor origin for id[%s]: %+v", id, anchorOriginResponse)

	latestAnchorOrigin, err := util.GetAnchorOrigin(anchorOriginResponse.DocumentMetadata)
	if err != nil {
		logger.Debugf("resolving locally since there was an error while getting remote anchor origin for id[%s]: %s",
			id, err.Error())

		return localResponse, nil
	}

	if localAnchorOrigin != latestAnchorOrigin {
		logger.Debugf("resolving locally since local and remote anchor origins don't match for id[%s]", id)

		return localResponse, nil
	}

	// parse anchor origin response to get unpublished and published operations
	anchorOriginUnpublishedOps, anchorOriginPublishedOps := getOperations(id, anchorOriginResponse.DocumentMetadata)

	logger.Debugf("parsed %d unpublished and %d published operations from anchor origin for id[%s]",
		len(anchorOriginUnpublishedOps), len(anchorOriginPublishedOps), id)

	// parse local response to get unpublished and published operations
	_, localPublishedOps := getOperations(id, localResponse.DocumentMetadata)

	additionalPublishedOps := getAdditionalPublishedOps(localPublishedOps, anchorOriginPublishedOps)

	anchorOriginOps := append(anchorOriginUnpublishedOps, additionalPublishedOps...)

	if len(anchorOriginOps) == 0 {
		logger.Debugf("resolving locally for id[%s] since anchor origin has no unpublished or additional published operations", id) //nolint:lll

		return localResponse, nil
	}

	// apply unpublished and additional published operations to local response
	// unpublished/additional published operations will be included in document metadata
	localResponseWithAnchorOriginOps, err := r.resolveDocumentLocally(id, anchorOriginOps...)
	if err != nil {
		logger.Debugf("resolving locally due to error in resolve doc locally with unpublished/additional published ops for id[%s]: %s", id, err.Error()) //nolint:lll

		return localResponse, nil
	}

	err = checkResponses(anchorOriginResponse, localResponseWithAnchorOriginOps)
	if err != nil {
		logger.Debugf("resolving locally due to matching error for id[%s]: %s", id, err.Error())

		return localResponse, nil
	}

	return localResponseWithAnchorOriginOps, nil
}

func getOperations(id string, metadata document.Metadata) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation) { //nolint:lll
	unpublishedOps, err := util.GetUnpublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debugf("unable to get unpublished operations for id[%s]: %s", id, err.Error())
	}

	publishedOps, err := util.GetPublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debugf("unable to get published operations for id[%s]: %s", id, err.Error())
	}

	return unpublishedOps, publishedOps
}

func getAdditionalPublishedOps(localOps, anchorOps []*operation.AnchoredOperation) []*operation.AnchoredOperation {
	if len(anchorOps) == 0 {
		// nothing to check since anchor origin published operations are not provided
		return nil
	}

	if len(localOps) == 0 {
		logger.Debugf("nothing to check since local published operations are not provided...")
		// nothing to check since local published operations are not provided
		return nil
	}

	// both local and anchor origin unpublished ops are provided - check if local head is in anchor origin history
	localHead := localOps[len(localOps)-1]

	return util.GetOperationsAfterCanonicalReference(localHead.CanonicalReference, anchorOps)
}

func checkResponses(anchorOrigin, local *document.ResolutionResult) error {
	err := equalDocuments(anchorOrigin.Document, local.Document)
	if err != nil {
		return err
	}

	return equalCommitments(anchorOrigin.DocumentMetadata, local.DocumentMetadata)
}

func equalDocuments(anchorOrigin, local document.Document) error {
	anchorOriginBytes, err := canonicalizer.MarshalCanonical(anchorOrigin)
	if err != nil {
		return fmt.Errorf("failed to marshal canonical anchor origin document: %w", err)
	}

	localBytes, err := canonicalizer.MarshalCanonical(local)
	if err != nil {
		return fmt.Errorf("failed to marshal canonical local document: %w", err)
	}

	if !bytes.Equal(anchorOriginBytes, localBytes) {
		return fmt.Errorf("anchor origin[%s] and local[%s] documents don't match",
			string(anchorOriginBytes), string(localBytes))
	}

	return nil
}

func equalCommitments(anchorOrigin, local document.Metadata) error {
	anchorOriginMethodMetadata, err := util.GetMethodMetadata(anchorOrigin)
	if err != nil {
		return fmt.Errorf("unable to get anchor origin metadata: %w", err)
	}

	localMethodMetadata, err := util.GetMethodMetadata(local)
	if err != nil {
		return fmt.Errorf("unable to get local metadata: %w", err)
	}

	err = checkCommitment(anchorOriginMethodMetadata, localMethodMetadata, document.UpdateCommitmentProperty)
	if err != nil {
		return fmt.Errorf("anchor origin and local update commitments don't match: %w", err)
	}

	err = checkCommitment(anchorOriginMethodMetadata, localMethodMetadata, document.RecoveryCommitmentProperty)
	if err != nil {
		return fmt.Errorf("anchor origin and local recovery commitments don't match: %w", err)
	}

	return nil
}

func checkCommitment(anchorOrigin, local map[string]interface{}, commitmentType string) error {
	ao, ok := anchorOrigin[commitmentType]
	if !ok {
		return fmt.Errorf("missing '%s' in anchor origin method metadata", commitmentType)
	}

	l, ok := local[commitmentType]
	if !ok {
		return fmt.Errorf("missing '%s' in local method metadata", commitmentType)
	}

	if ao != l {
		return fmt.Errorf("anchor origin value[%s] is different from local value[%s]", ao, l)
	}

	return nil
}

func (r *ResolveHandler) resolveDocumentFromAnchorOrigin(id, anchorOrigin string) (*document.ResolutionResult, error) { //nolint:lll
	endpoint, err := r.getAnchorOriginEndpoint(anchorOrigin)
	if err != nil {
		return nil, err
	}

	resolveDocumentFromAnchorOriginStartTime := time.Now()

	defer func() {
		r.metrics.ResolveDocumentFromAnchorOriginTime(time.Since(resolveDocumentFromAnchorOriginStartTime))
	}()

	anchorOriginResponse, err := r.remoteResolver.ResolveDocumentFromResolutionEndpoints(id, endpoint.ResolutionEndpoints)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve id[%s] from anchor origin endpoints%s: %w",
			id, endpoint.ResolutionEndpoints, err)
	}

	return anchorOriginResponse, nil
}

func (r *ResolveHandler) getAnchorOriginEndpoint(anchorOrigin string) (*models.Endpoint, error) {
	getAnchorOriginEndpointStartTime := time.Now()

	defer func() {
		r.metrics.GetAnchorOriginEndpointTime(time.Since(getAnchorOriginEndpointStartTime))
	}()

	endpoint, err := r.endpointClient.GetEndpoint(anchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("unable to get endpoint from anchor origin domain[%s]: %w", anchorOrigin, err)
	}

	return endpoint, nil
}

func (r *ResolveHandler) resolveDocumentLocally(id string, additionalOps ...*operation.AnchoredOperation) (*document.ResolutionResult, error) { //nolint:lll,gocyclo,cyclop
	resolveDocumentLocallyStartTime := time.Now()

	defer func() {
		r.metrics.ResolveDocumentLocallyTime(time.Since(resolveDocumentLocallyStartTime))
	}()

	response, err := r.coreResolver.ResolveDocument(id, additionalOps...)
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
	deleteDocumentFromCreateDocumentStoreStartTime := time.Now()

	defer func() {
		r.metrics.DeleteDocumentFromCreateDocumentStoreTime(time.Since(deleteDocumentFromCreateDocumentStoreStartTime))
	}()

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
	resolveDocumentFromCreateDocumentStoreStartTime := time.Now()

	defer func() {
		r.metrics.ResolveDocumentFromCreateDocumentStoreTime(time.Since(resolveDocumentFromCreateDocumentStoreStartTime))
	}()

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

	if rr.Document.ID() == id {
		return &rr, nil
	}

	// document is requested with different ID than ID used in create response
	// for created document equivalent ID (with https hint) is also valid ID

	equivalentID := getEquivalentID(rr.DocumentMetadata)
	if equivalentID != id {
		logger.Debugf("requested id[%s] does not match create id[%s] or equivalent id[%s] for created document", id, rr.Document.ID(), equivalentID) //nolint:lll

		return nil, fmt.Errorf("requested id[%s] does not match create id[%s] or equivalent id[%s] for created document", id, rr.Document.ID(), equivalentID) //nolint:lll
	}

	// id matches equivalent ID - replace all occurrences of ID with equivalent ID
	docWithEquivalentID := strings.ReplaceAll(string(createDocBytes), rr.Document.ID(), equivalentID)

	err = json.Unmarshal([]byte(docWithEquivalentID), &rr)
	if err != nil {
		logger.Warnf("failed to marshal document with equivalent id[%s] from create document store: %s", id, err.Error())

		return nil, err
	}

	return &rr, nil
}

func getEquivalentID(metadata document.Metadata) string {
	equivalentIdsObj, ok := metadata[document.EquivalentIDProperty]
	if !ok {
		return ""
	}

	equivalentIds, ok := equivalentIdsObj.([]interface{})
	if !ok {
		return ""
	}

	if len(equivalentIds) > 0 {
		return equivalentIds[0].(string)
	}

	return ""
}

func (r *ResolveHandler) requestDiscovery(did string) {
	logger.Infof("requesting discovery for did[%s]", did)

	requestDiscoveryStartTime := time.Now()

	defer func() {
		r.metrics.RequestDiscoveryTime(time.Since(requestDiscoveryStartTime))
	}()

	err := r.discoveryService.RequestDiscovery(did)
	if err != nil {
		logger.Warnf("error while requesting discovery for did[%s]: %s", did, err.Error())
	}
}

func (r *ResolveHandler) verifyCID(id string, rr *document.ResolutionResult) error {
	verifyCIDStartTime := time.Now()

	defer func() {
		r.metrics.VerifyCIDTime(time.Since(verifyCIDStartTime))
	}()

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
