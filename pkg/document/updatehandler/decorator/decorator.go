/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"context"
	"fmt"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-go/pkg/document"
	"github.com/trustbloc/sidetree-go/pkg/docutil"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

var logger = log.New("operation-decorator")

const propCreatePublished = "create-op-is-published"

// New creates operation decorator that will verify that local domain has latest operations from anchor origin.
func New(namespace, domain string, processor operationProcessor, endpointClient endpointClient,
	remoteResolver remoteResolver, verifyLatestFromAnchorOrigin bool, metrics metricsProvider,
) *OperationDecorator {
	od := &OperationDecorator{
		namespace:                    namespace,
		domain:                       domain,
		processor:                    processor,
		endpointClient:               endpointClient,
		remoteResolver:               remoteResolver,
		verifyLatestFromAnchorOrigin: verifyLatestFromAnchorOrigin,
		metrics:                      metrics,
		tracer:                       tracing.Tracer(tracing.SubsystemDocument),
	}

	return od
}

// OperationDecorator is operation decorator.
type OperationDecorator struct {
	namespace string
	domain    string

	verifyLatestFromAnchorOrigin bool

	processor operationProcessor

	remoteResolver remoteResolver
	endpointClient endpointClient

	metrics metricsProvider
	tracer  trace.Tracer
}

// operationProcessor is an interface which resolves the document based on the unique suffix.
type operationProcessor interface {
	Resolve(uniqueSuffix string, opts ...document.ResolutionOption) (*protocol.ResolutionModel, error)
}

type endpointClient interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
}

type remoteResolver interface {
	ResolveDocumentFromResolutionEndpoints(ctx context.Context, id string, endpoints []string) (*document.ResolutionResult, error)
}

type metricsProvider interface {
	DecorateTime(duration time.Duration)
	ProcessorResolveTime(duration time.Duration)
	GetAOEndpointAndResolveDocumentFromAOTime(duration time.Duration)
}

// Decorate will validate local state against anchor origin for update/recover/deactivate.
func (d *OperationDecorator) Decorate(op *operation.Operation) (*operation.Operation, error) {
	startTime := time.Now()

	defer func() {
		d.metrics.DecorateTime(time.Since(startTime))
	}()

	if op.Type == operation.TypeCreate {
		return op, nil
	}

	processorResolveStartTime := time.Now()

	internalResult, err := d.processor.Resolve(op.UniqueSuffix)

	d.metrics.ProcessorResolveTime(time.Since(processorResolveStartTime))

	if err != nil {
		logger.Info("Failed to resolve suffix[%s] for operation type[%s]: %s", logfields.WithSuffix(op.UniqueSuffix),
			logfields.WithOperationType(string(op.Type)), log.WithError(err))

		return nil, err
	}

	logger.Debug("Processor returned internal result", logfields.WithSuffix(op.UniqueSuffix),
		logfields.WithOperationType(string(op.Type)), logfields.WithResolutionModel(internalResult))

	if internalResult.Deactivated {
		return nil, fmt.Errorf("document has been deactivated, no further operations are allowed")
	}

	d.checkCreateOperationPublished(op, internalResult)

	if d.verifyLatestFromAnchorOrigin {
		return d.verifyFromAnchorOrigin(op, internalResult)
	}

	return op, nil
}

// checkCreateOperationPublished checks that the "Create" operation was published and sets the "create-op-is-published"
// property on the operation. This property is used by the operation queue to determine whether to add a delivery delay.
func (d *OperationDecorator) checkCreateOperationPublished(op *operation.Operation,
	internalResult *protocol.ResolutionModel,
) *operation.Operation {
	var createOperationIsPublished bool

	for _, pop := range internalResult.PublishedOperations {
		if pop.Type == operation.TypeCreate {
			createOperationIsPublished = true

			break
		}
	}

	op.Properties = append(op.Properties, operation.Property{
		Key:   propCreatePublished,
		Value: createOperationIsPublished,
	})

	return op
}

func (d *OperationDecorator) verifyFromAnchorOrigin(op *operation.Operation,
	internalResult *protocol.ResolutionModel,
) (*operation.Operation, error) {
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

	ctx, span := d.tracer.Start(context.Background(), "decorate")
	defer span.End()

	anchorOriginResponse, err := d.resolveDocumentFromAnchorOrigin(ctx, canonicalID, localAnchorOrigin)
	if err != nil {
		logger.Warnc(ctx, "Failed to resolve document from anchor origin. The local document will be used.",
			logfields.WithDID(canonicalID), log.WithError(err))

		return op, nil
	}

	d.metrics.GetAOEndpointAndResolveDocumentFromAOTime(time.Since(resolveFromAnchorOriginTime))

	latestAnchorOrigin, err := util.GetAnchorOrigin(anchorOriginResponse.DocumentMetadata)
	if err != nil {
		// this should never happen
		return nil, fmt.Errorf("failed to retrieve DID's anchor origin from anchor origin domain: %w", err)
	}

	if localAnchorOrigin != latestAnchorOrigin {
		return nil, fmt.Errorf("anchor origin has different anchor origin for this did - please re-submit your request at later time")
	}

	logger.Debugc(ctx, "Got resolution response from anchor origin", logfields.WithDID(canonicalID),
		logfields.WithResolutionResult(anchorOriginResponse))

	// parse anchor origin response to get unpublished and published operations
	anchorOriginUnpublishedOps, anchorOriginPublishedOps := getOperations(canonicalID, anchorOriginResponse.DocumentMetadata)

	if len(anchorOriginPublishedOps) == 0 {
		// published ops not provided at anchor origin - nothing to do
		logger.Debugc(ctx, "Published ops not provided at anchor origin - nothing to check", logfields.WithDID(canonicalID))

		return op, nil
	}

	if len(internalResult.PublishedOperations) == 0 {
		// this should never happen
		return nil, fmt.Errorf("local server has no published operations for suffix[%s]", op.UniqueSuffix)
	}

	localHead := internalResult.PublishedOperations[len(internalResult.PublishedOperations)-1].CanonicalReference

	if len(anchorOriginUnpublishedOps) > 0 {
		return nil, fmt.Errorf("anchor origin has unpublished operations - please re-submit your request at later time")
	}

	if len(util.GetOperationsAfterCanonicalReference(localHead, anchorOriginPublishedOps)) > 0 {
		return nil, fmt.Errorf("anchor origin has additional published operations - please re-submit your request at later time")
	}

	return op, nil
}

func (d *OperationDecorator) resolveDocumentFromAnchorOrigin(ctx context.Context,
	id, anchorOrigin string,
) (*document.ResolutionResult, error) {
	endpoint, err := d.endpointClient.GetEndpoint(anchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("unable to get endpoint from anchor origin domain[%s]: %w", id, err)
	}

	logger.Debug("Got anchor domain resolution endpoints", logfields.WithDID(id),
		logfields.WithResolutionEndpoints(endpoint.ResolutionEndpoints...))

	anchorOriginResponse, err := d.remoteResolver.ResolveDocumentFromResolutionEndpoints(ctx, id, endpoint.ResolutionEndpoints)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve id[%s] from anchor origin endpoints%s: %w",
			id, endpoint.ResolutionEndpoints, err)
	}

	return anchorOriginResponse, nil
}

func getOperations(id string, metadata document.Metadata) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation) {
	unpublishedOps, err := util.GetUnpublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get unpublished operations", logfields.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed unpublished operations from anchor origin", logfields.WithDID(id),
			logfields.WithTotal(len(unpublishedOps)))
	}

	publishedOps, err := util.GetPublishedOperationsFromMetadata(metadata)
	if err != nil {
		logger.Debug("Unable to get published operations", logfields.WithDID(id), log.WithError(err))
	} else {
		logger.Debug("Parsed published operations from anchor origin", logfields.WithDID(id),
			logfields.WithTotal(len(publishedOps)))
	}

	return unpublishedOps, publishedOps
}
