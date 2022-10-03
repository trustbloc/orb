/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"fmt"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/util"
)

var logger = log.NewStructured("operation-decorator")

// New creates operation decorator that will verify that local domain has latest operations from anchor origin.
func New(namespace, domain string, processor operationProcessor,
	endpointClient endpointClient, remoteResolver remoteResolver, metrics metricsProvider) *OperationDecorator {
	od := &OperationDecorator{
		namespace:      namespace,
		domain:         domain,
		processor:      processor,
		endpointClient: endpointClient,
		remoteResolver: remoteResolver,
		metrics:        metrics,
	}

	return od
}

// OperationDecorator is operation decorator.
type OperationDecorator struct {
	namespace string
	domain    string

	processor operationProcessor

	remoteResolver remoteResolver
	endpointClient endpointClient

	metrics metricsProvider
}

// operationProcessor is an interface which resolves the document based on the unique suffix.
type operationProcessor interface {
	Resolve(uniqueSuffix string, opts ...document.ResolutionOption) (*protocol.ResolutionModel, error)
}

type endpointClient interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
}

type remoteResolver interface {
	ResolveDocumentFromResolutionEndpoints(id string, endpoints []string) (*document.ResolutionResult, error)
}

type metricsProvider interface {
	DecorateTime(duration time.Duration)
	ProcessorResolveTime(duration time.Duration)
	GetAOEndpointAndResolveDocumentFromAOTime(duration time.Duration)
}

// Decorate will validate local state against anchor origin for update/recover/deactivate.
func (d *OperationDecorator) Decorate(op *operation.Operation) (*operation.Operation, error) { //nolint:lll,funlen,gocyclo,cyclop
	startTime := time.Now()

	defer func() {
		d.metrics.DecorateTime(time.Since(startTime))
	}()

	if op.Type == operation.TypeCreate {
		return op, nil
	}

	processorResolveStartTime := time.Now()

	internalResult, err := d.processor.Resolve(op.UniqueSuffix)
	if err != nil {
		logger.Debug("Failed to resolve suffix[%s] for operation type[%s]: %s", log.WithSuffix(op.UniqueSuffix),
			log.WithOperationType(string(op.Type)), log.WithError(err))

		return nil, err
	}

	logger.Debug("Processor returned internal result", log.WithSuffix(op.UniqueSuffix),
		log.WithOperationType(string(op.Type)), log.WithResolutionModel(internalResult))

	if internalResult.Deactivated {
		return nil, fmt.Errorf("document has been deactivated, no further operations are allowed")
	}

	d.metrics.ProcessorResolveTime(time.Since(processorResolveStartTime))

	if op.Type == operation.TypeUpdate || op.Type == operation.TypeDeactivate {
		op.AnchorOrigin = internalResult.AnchorOrigin
	}

	canonicalID := d.namespace + docutil.NamespaceDelimiter +
		internalResult.CanonicalReference + docutil.NamespaceDelimiter + op.UniqueSuffix

	localAnchorOrigin, ok := internalResult.AnchorOrigin.(string)
	if !ok {
		// this should never happen locally
		return nil, fmt.Errorf("anchor origin is not a string in local result for suffix[%s]", op.UniqueSuffix)
	}

	if localAnchorOrigin == d.domain {
		// local domain is anchor origin - nothing else to check
		return op, nil
	}

	resolveFromAnchorOriginTime := time.Now()

	anchorOriginResponse, err := d.resolveDocumentFromAnchorOrigin(canonicalID, localAnchorOrigin)
	if err != nil {
		logger.Debug("Failed to resolve document from anchor origin", log.WithDID(canonicalID), log.WithError(err))

		return op, nil
	}

	d.metrics.GetAOEndpointAndResolveDocumentFromAOTime(time.Since(resolveFromAnchorOriginTime))

	latestAnchorOrigin, err := util.GetAnchorOrigin(anchorOriginResponse.DocumentMetadata)
	if err != nil {
		// this should never happen
		return nil, fmt.Errorf("failed to retrieve DID's anchor origin from anchor origin domain: %w", err)
	}

	if localAnchorOrigin != latestAnchorOrigin {
		return nil, fmt.Errorf("anchor origin has different anchor origin for this did - please re-submit your request at later time") //nolint:lll
	}

	logger.Debug("Got resolution response from anchor origin", log.WithDID(canonicalID),
		log.WithResolutionResult(anchorOriginResponse))

	// parse anchor origin response to get unpublished and published operations
	anchorOriginUnpublishedOps, anchorOriginPublishedOps := getOperations(canonicalID, anchorOriginResponse.DocumentMetadata) //nolint:lll

	if len(anchorOriginPublishedOps) == 0 {
		// published ops not provided at anchor origin - nothing to do
		logger.Debug("Published ops not provided at anchor origin - nothing to check", log.WithDID(canonicalID))

		return op, nil
	}

	if len(internalResult.PublishedOperations) == 0 {
		// this should never happen
		return nil, fmt.Errorf("local server has no published operations for suffix[%s]", op.UniqueSuffix)
	}

	localHead := internalResult.PublishedOperations[len(internalResult.PublishedOperations)-1].CanonicalReference

	if len(anchorOriginUnpublishedOps) > 0 {
		return nil, fmt.Errorf("anchor origin has unpublished operations - please re-submit your request at later time") //nolint:lll
	}

	if len(util.GetOperationsAfterCanonicalReference(localHead, anchorOriginPublishedOps)) > 0 {
		return nil, fmt.Errorf("anchor origin has additional published operations - please re-submit your request at later time") //nolint:lll
	}

	return op, nil
}

func (d *OperationDecorator) resolveDocumentFromAnchorOrigin(id, anchorOrigin string) (*document.ResolutionResult, error) { //nolint:lll
	endpoint, err := d.endpointClient.GetEndpoint(anchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("unable to get endpoint from anchor origin domain[%s]: %w", id, err)
	}

	logger.Debug("Got anchor domain resolution endpoints", log.WithDID(id),
		log.WithResolutionEndpoints(endpoint.ResolutionEndpoints...))

	anchorOriginResponse, err := d.remoteResolver.ResolveDocumentFromResolutionEndpoints(id, endpoint.ResolutionEndpoints)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve id[%s] from anchor origin endpoints%s: %w",
			id, endpoint.ResolutionEndpoints, err)
	}

	return anchorOriginResponse, nil
}

func getOperations(id string, metadata document.Metadata) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation) { //nolint:lll
	unpublishedOps, err := util.GetUnpublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get unpublished operations", log.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed unpublished operations from anchor origin", log.WithDID(id),
			log.WithTotal(len(unpublishedOps)))
	}

	publishedOps, err := util.GetPublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get published operations", log.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed published operations from anchor origin", log.WithDID(id),
			log.WithTotal(len(publishedOps)))
	}

	return unpublishedOps, publishedOps
}
