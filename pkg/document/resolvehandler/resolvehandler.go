/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

var logger = log.New("orb-resolver")

// ErrDocumentNotFound is document not found error.
var ErrDocumentNotFound = fmt.Errorf("document not found")

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	coreResolver coreResolver
	anchorGraph  common.AnchorGraph
	metrics      metricsProvider
	tracer       trace.Tracer

	discoveryService discoveryService
	remoteResolver   remoteResolver
	endpointClient   endpointClient

	namespace string
	domain    string

	unpublishedDIDLabel string

	enableDidDiscovery bool

	enableResolutionFromAnchorOrigin bool

	hl *hashlink.HashLink
}

// Resolver resolves documents.
type coreResolver interface {
	ResolveDocument(idOrDocument string, opts ...document.ResolutionOption) (*document.ResolutionResult, error)
}

// did discovery service.
type discoveryService interface {
	RequestDiscovery(ctx context.Context, id string) error
}

type endpointClient interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
	ResolveDomainForDID(id string) (string, error)
	GetDomainFromIPNS(uri string) (string, error)
}

type remoteResolver interface {
	ResolveDocumentFromResolutionEndpoints(ctx context.Context, id string, endpoints []string) (*document.ResolutionResult, error)
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
		tracer:           tracing.Tracer(tracing.SubsystemDocument),
		hl:               hashlink.New(),
	}

	// apply options
	for _, opt := range opts {
		opt(rh)
	}

	return rh
}

// ResolveDocument resolves a document.
func (r *ResolveHandler) ResolveDocument(id string, opts ...document.ResolutionOption) (*document.ResolutionResult, error) {
	startTime := time.Now()

	defer func() {
		r.metrics.DocumentResolveTime(time.Since(startTime))
	}()

	ctx, span := r.tracer.Start(context.Background(), "resolve document")
	defer span.End()

	localResponse, err := r.resolveDocumentLocally(ctx, id, opts...)
	if err != nil {
		return nil, fmt.Errorf("resolve document [%s] locally: %w", id, err)
	}

	if r.enableResolutionFromAnchorOrigin && !strings.Contains(id, r.unpublishedDIDLabel) {
		return r.resolveDocumentFromAnchorOriginAndCombineWithLocal(ctx, id, localResponse, opts...), nil
	}

	return localResponse, nil
}

//nolint:funlen,cyclop
func (r *ResolveHandler) resolveDocumentFromAnchorOriginAndCombineWithLocal(
	ctx context.Context, id string, localResponse *document.ResolutionResult,
	opts ...document.ResolutionOption) *document.ResolutionResult {
	localAnchorOrigin, err := util.GetAnchorOrigin(localResponse.DocumentMetadata)
	if err != nil {
		logger.Debug(
			"Resolving locally since there was an error getting anchor origin from local response",
			logfields.WithDID(id), log.WithError(err))

		// this error should never happen - return local response
		return localResponse
	}

	var domain string

	switch {
	case util.IsDID(localAnchorOrigin):
		domain, err = r.endpointClient.ResolveDomainForDID(localAnchorOrigin)
		if err != nil {
			logger.Debug("Resolving locally since there was an error getting domain",
				logfields.WithDID(id), log.WithError(err))

			return localResponse
		}
	case strings.HasPrefix(localAnchorOrigin, "ipns://"):
		domain, err = r.endpointClient.GetDomainFromIPNS(localAnchorOrigin)

		if err != nil {
			logger.Debug("Resolving locally since there was an error getting domain from ipns",
				logfields.WithDID(id), log.WithError(err))

			return localResponse
		}
	default:
		domain = localAnchorOrigin
	}

	logger.Debug("Resolved domain", logfields.WithDID(id), logfields.WithDomain(domain))

	if domain == r.domain {
		logger.Debug("Nothing to do since local anchor origin domain equals current domain",
			logfields.WithAnchorOrigin(localAnchorOrigin), logfields.WithDID(id), logfields.WithDomain(r.domain))

		// nothing to do since DID's anchor origin equals current domain - return local response
		return localResponse
	}

	anchorOriginResponse, err := r.resolveDocumentFromAnchorOrigin(ctx, id, localAnchorOrigin)
	if err != nil {
		logger.Warn("Resolving locally since there was an error getting local anchor origin",
			logfields.WithDID(id), log.WithError(err))

		return localResponse
	}

	logger.Debug("Resolution response from anchor origin", logfields.WithDID(id),
		logfields.WithResolutionResult(anchorOriginResponse))

	latestAnchorOrigin, err := util.GetAnchorOrigin(anchorOriginResponse.DocumentMetadata)
	if err != nil {
		logger.Warn("Resolving locally since there was an error getting remote anchor origin",
			logfields.WithDID(id), log.WithError(err))

		return localResponse
	}

	if localAnchorOrigin != latestAnchorOrigin {
		logger.Debug("Resolving locally since local and remote anchor origins don't match", logfields.WithDID(id))

		return localResponse
	}

	// parse anchor origin response to get unpublished and published operations
	anchorOriginUnpublishedOps, anchorOriginPublishedOps := getOperations(id, anchorOriginResponse.DocumentMetadata)

	// parse local response to get unpublished and published operations
	_, localPublishedOps := getOperations(id, localResponse.DocumentMetadata)

	additionalPublishedOps := getAdditionalPublishedOps(id, localPublishedOps, anchorOriginPublishedOps)

	anchorOriginOps := append(anchorOriginUnpublishedOps, additionalPublishedOps...) //nolint: gocritic

	if len(anchorOriginOps) == 0 {
		logger.Debug("Resolving locally since anchor origin has no unpublished or additional published operations",
			logfields.WithDID(id))

		return localResponse
	}

	// apply unpublished and additional published operations to local response
	// unpublished/additional published operations will be included in document metadata

	opts = append(opts, document.WithAdditionalOperations(anchorOriginOps))

	localResponseWithAnchorOriginOps, err := r.resolveDocumentLocally(ctx, id, opts...)
	if err != nil {
		logger.Debug("Resolving locally due to error in resolve doc locally with unpublished/additional published ops",
			logfields.WithDID(id), log.WithError(err))

		return localResponse
	}

	err = checkResponses(anchorOriginResponse, localResponseWithAnchorOriginOps)
	if err != nil {
		logger.Debug("Resolving locally due to matching error", logfields.WithDID(id), log.WithError(err))

		return localResponse
	}

	return localResponseWithAnchorOriginOps
}

func getOperations(id string, metadata document.Metadata) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation) {
	unpublishedOps, err := util.GetUnpublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get unpublished operations", logfields.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed unpublished from anchor origin",
			logfields.WithTotal(len(unpublishedOps)), logfields.WithDID(id))
	}

	publishedOps, err := util.GetPublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get published operations", logfields.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed published operations from anchor origin",
			logfields.WithTotal(len(publishedOps)), logfields.WithDID(id))
	}

	return unpublishedOps, publishedOps
}

func getAdditionalPublishedOps(id string, localOps,
	anchorOps []*operation.AnchoredOperation) []*operation.AnchoredOperation {
	if len(anchorOps) == 0 {
		logger.Debug("Nothing to check since anchor origin published operations are not provided.",
			logfields.WithDID(id))

		return nil
	}

	if len(localOps) == 0 {
		logger.Debug("Nothing to check since local published operations are not provided.", logfields.WithDID(id))

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

	return equalMetadata(anchorOrigin.DocumentMetadata, local.DocumentMetadata)
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

func equalMetadata(anchorOrigin, local document.Metadata) error {
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

	if anchorOriginMethodMetadata[document.AnchorOriginProperty] != localMethodMetadata[document.AnchorOriginProperty] {
		return fmt.Errorf("anchor origin[%s] and local[%s] anchor origins don't match",
			anchorOriginMethodMetadata[document.AnchorOriginProperty], localMethodMetadata[document.AnchorOriginProperty])
	}

	if anchorOrigin[document.CanonicalIDProperty] != local[document.CanonicalIDProperty] {
		return fmt.Errorf("anchor origin[%s] and local[%s] canonical IDs don't match",
			anchorOrigin[document.CanonicalIDProperty], local[document.CanonicalIDProperty])
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

func (r *ResolveHandler) resolveDocumentFromAnchorOrigin(ctx context.Context, id, anchorOrigin string) (*document.ResolutionResult, error) {
	endpoint, err := r.getAnchorOriginEndpoint(anchorOrigin)
	if err != nil {
		return nil, err
	}

	resolveDocumentFromAnchorOriginStartTime := time.Now()

	defer func() {
		r.metrics.ResolveDocumentFromAnchorOriginTime(time.Since(resolveDocumentFromAnchorOriginStartTime))
	}()

	anchorOriginResponse, err := r.remoteResolver.ResolveDocumentFromResolutionEndpoints(ctx, id, endpoint.ResolutionEndpoints)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve id[%s] from anchor origin endpoints%s: %w",
			id, endpoint.ResolutionEndpoints, err)
	}

	logger.Debug("... successfully resolved document from anchor origin", logfields.WithDID(id),
		logfields.WithAnchorOrigin(anchorOrigin), logfields.WithResolutionResult(anchorOriginResponse))

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

func (r *ResolveHandler) resolveDocumentLocally(ctx context.Context, id string,
	opts ...document.ResolutionOption) (*document.ResolutionResult, error) {
	resolveDocumentLocallyStartTime := time.Now()

	defer func() {
		r.metrics.ResolveDocumentLocallyTime(time.Since(resolveDocumentLocallyStartTime))
	}()

	response, err := r.coreResolver.ResolveDocument(id, opts...)
	if err != nil {
		if strings.Contains(err.Error(), "not found") &&
			!strings.Contains(id, r.unpublishedDIDLabel) &&
			r.enableDidDiscovery {
			r.requestDiscovery(ctx, id)
		}

		return nil, fmt.Errorf("resolve document [%s]: %w", id, err)
	}

	// document was retrieved from operation store

	if !strings.Contains(id, r.unpublishedDIDLabel) {
		// we have to check if CID belongs to the resolved document
		err = r.verifyCID(id, response)
		if err != nil {
			return nil, fmt.Errorf("verify CID [%s]: %w", id, err)
		}
	}

	return response, nil
}

func (r *ResolveHandler) requestDiscovery(ctx context.Context, did string) {
	logger.Info("Requesting discovery for DID", logfields.WithDID(did))

	requestDiscoveryStartTime := time.Now()

	defer func() {
		r.metrics.RequestDiscoveryTime(time.Since(requestDiscoveryStartTime))
	}()

	err := r.discoveryService.RequestDiscovery(ctx, did)
	if err != nil {
		logger.Warn("Error while requesting discovery for DID", logfields.WithDID(did), log.WithError(err))
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

	logger.Debug("Resolved CID doesn't match requested CID in DID - check anchor graph for requested CID",
		logfields.WithResolvedCID(resolvedCID), logfields.WithCID(cidFromID), logfields.WithDID(id))

	return r.verifyCIDExistenceInAnchorGraph(cidFromID, resolvedCID, suffix)
}

func (r *ResolveHandler) verifyCIDExistenceInAnchorGraph(cid, anchorCID, anchorSuffix string) error {
	anchors, err := r.anchorGraph.GetDidAnchors(hashlink.GetHashLinkFromResourceHash(anchorCID), anchorSuffix)
	if err != nil {
		return fmt.Errorf("get DID anchors for CID [%s]: %w", anchorCID, err)
	}

	for _, anchor := range anchors {
		if strings.Contains(anchor.CID, cid) {
			// if requested CID is an old CID we should return found
			return nil
		}
	}

	logger.Debug("CID not found in anchor graph starting from cid[%s] and suffix", logfields.WithCID(cid),
		logfields.WithAnchorCID(anchorCID), logfields.WithSuffix(anchorSuffix))

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

	logger.Debug("Returning CID and suffix for DID", logfields.WithCID(cid), logfields.WithSuffix(suffix), logfields.WithDID(id))

	return cid, suffix, nil
}
