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
)

const (
	namespace = "did:orb"
	domain    = "https://domain.com"

	anchorOriginDomain = "https://anchor-origin.domain.com"
)

//go:generate counterfeiter -o ../../mocks/operationprocessor.gen.go --fake-name OperationProcessor . operationProcessor

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := New(namespace, domain, &mocks.OperationProcessor{}, &mocks.EndpointClient{}, &mocks.RemoteResolver{})
		require.NotNil(t, handler)
	})
}

func TestOperationDecorator_Decorate(t *testing.T) {
	const suffix = "suffix"

	t.Run("success - operation accepted (local domain operations match anchor origin operations)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("success - operation accepted (local domain equals anchor origin domain)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        domain,
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
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
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
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
		handler := New(namespace, domain, &mocks.OperationProcessor{}, &mocks.EndpointClient{}, &mocks.RemoteResolver{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeCreate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("success - endpoint client error (ignored)", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(nil, fmt.Errorf("endpoint client error"))

		handler := New(namespace, domain, processor, endpointClient, &mocks.RemoteResolver{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{Type: operation.TypeUpdate, UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("error - operation processor error", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(nil, fmt.Errorf("operation processor error"))

		handler := New(namespace, domain, processor, &mocks.EndpointClient{}, &mocks.RemoteResolver{})
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: suffix})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "operation processor error")
	})

	t.Run("success - remote resolver error", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
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
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: suffix})
		require.NoError(t, err)
		require.NotNil(t, op)
	})

	t.Run("error - anchor origin has additional operations", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{
			PublishedOperations: []*operation.AnchoredOperation{
				{Type: operation.TypeCreate, UniqueSuffix: suffix, CanonicalReference: "abc"},
			},
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
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
		}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(),
			"anchor origin has unpublished operations - please re-submit your request at later time")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "local server has no published operations for suffix[suffix]")
	})

	t.Run("success - no published operations from anchor origin", func(t *testing.T) {
		processor := &mocks.OperationProcessor{}
		processor.ResolveReturns(&protocol.ResolutionModel{}, nil)

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})
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

		handler := New(namespace, domain, processor, endpointClient, remoteResolver)
		require.NotNil(t, handler)

		op, err := handler.Decorate(&operation.Operation{UniqueSuffix: "suffix"})
		require.NoError(t, err)
		require.NotNil(t, op)
	})
}
