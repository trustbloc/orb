/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/mocks"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

const (
	namespace = "did:orb"
	domain    = "https://domain.com"

	anchorOriginDomain = "https://anchor-origin.domain.com"
)

//go:generate counterfeiter -o ../../mocks/operationprocessor.gen.go --fake-name OperationProcessor . operationProcessor

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := New(namespace, domain, &mocks.OperationProcessor{},
			&mocks.EndpointClient{}, &mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)
	})
}

//nolint:maintidx
func TestOperationDecorator_Decorate(t *testing.T) {
	const suffix = "suffix"

	t.Run("success - operation accepted (local domain operations match anchor origin operations)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
			AnchorOrigin: anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc"},
		}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps
		methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("success - operation accepted (local domain equals anchor origin domain)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			AnchorOrigin: domain,
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", domain)},
			}, nil)

		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc"},
		}

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("success - remote resolver error (ignored)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
			AnchorOrigin: anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc"},
		}

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(nil, fmt.Errorf("remote resolver error"))

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{
			Type:         operation.TypeRecover,
			UniqueSuffix: suffix,
			AnchorOrigin: "test.com",
		})
		require.NoError(t, err)
		require.NotNil(t, op)
		require.Equal(t, "test.com", op.AnchorOrigin)
	})

	t.Run("success - create operations", func(t *testing.T) {
		handler := New(namespace, domain, &mocks.OperationProcessor{},
			&mocks.EndpointClient{}, &mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeCreate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("error - local anchor origin not a string", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			AnchorOrigin: 123,
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}

		handler := New(namespace, domain, processor, endpointClient, &mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "anchor origin is not a string in local result for suffix[suffix]")
	})

	t.Run("error - local and remote anchor origin don't match", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
			AnchorOrigin: anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = "different.com"

		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc"},
		}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(),
			"anchor origin has different anchor origin for this did - please re-submit your request at later time")
	})

	t.Run("error - remote anchor origin invalid", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
			AnchorOrigin: anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = 123

		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc"},
		}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(),
			"failed to retrieve DID's anchor origin from anchor origin domain: anchor origin property is not a string")
	})

	t.Run("success - endpoint client error (ignored)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			AnchorOrigin: anchorOriginDomain,
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(nil, fmt.Errorf("endpoint client error"))

		handler := New(namespace, domain, processor, endpointClient, &mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("error - operation processor error", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(nil, fmt.Errorf("operation processor error"))

		handler := New(namespace, domain, processor, &mocks.EndpointClient{},
			&mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "operation processor error")
	})

	t.Run("error - document has been deactivated, no further operations allowed", func(t *testing.T) {
		rm := &protocol.ResolutionModel{
			Deactivated: true,
		}

		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(rm, nil)

		handler := New(namespace, domain, processor, &mocks.EndpointClient{},
			&mocks.RemoteResolver{}, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "document has been deactivated, no further operations are allowed")
	})

	t.Run("error - anchor origin has additional operations", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
			AnchorOrigin: anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

		publishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "abc", TransactionTime: 1},
			{Type: operation.TypeUpdate, CanonicalReference: "xyz", TransactionTime: 2},
		}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(),
			"anchor origin has additional published operations - please re-submit your request at later time")
	})

	t.Run("error - anchor origin has unpublished operations", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{{}},
			AnchorOrigin:        anchorOriginDomain,
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeCreate}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(),
			"anchor origin has unpublished operations - please re-submit your request at later time")
	})

	t.Run("error - internal server error(local server has no published operations)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{AnchorOrigin: anchorOriginDomain}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeCreate}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "local server has no published operations for suffix[suffix]")
	})

	t.Run("success - no published operations from anchor origin", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{AnchorOrigin: anchorOriginDomain}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointReturns(
			&models.Endpoint{
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "id"

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver, true, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.NoError(t, err)
		require.NotNil(t, op)
	})
}
