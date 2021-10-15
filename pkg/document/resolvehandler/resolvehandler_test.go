/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

//go:generate counterfeiter -o ./mocks/dochandler.gen.go --fake-name Resolver . coreResolver
//go:generate counterfeiter -o ./mocks/discovery.gen.go --fake-name Discovery . discoveryService
//go:generate counterfeiter -o ./mocks/endpointclient.gen.go --fake-name EndpointClient . endpointClient
//go:generate counterfeiter -o ./mocks/remoteresolver.gen.go --fake-name RemoteResolver . remoteResolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/mocks"
	"github.com/trustbloc/orb/pkg/document/util"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testNS    = "did:orb"
	testLabel = "uAAA"

	testDID               = "did:orb:cid:suffix"
	testDIDWithCIDAndHint = "did:orb:webcas:domain.com:cid:suffix"

	testDIDWithHL    = "did:orb:hl:uEiAK4KusHyrEyiNE2fdYuOJQG8t55w6XqFdloCdKW-0jnA:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQUs0S3VzSHlyRXlpTkUyZmRZdU9KUUc4dDU1dzZYcUZkbG9DZEtXLTBqbkF4QmlwZnM6Ly9iYWZrcmVpYWs0Y3YyeWh6a3l0ZmNncmd6NjVtbHJ5c3FkcGZ4dHp5b3M2dWZvem5hZTVmZngzamR0cQ:EiAE6sz3Y4_87zWXG_lLV-IahvMqfBRhbi482JClS6xpuw" //nolint:lll
	testDIDCanonical = "did:orb:hl:uEiAK4KusHyrEyiNE2fdYuOJQG8t55w6XqFdloCdKW-0jnA:EiAE6sz3Y4_87zWXG_lLV-IahvMqfBRhbi482JClS6xpuw"                                                                                                                                                                                                         //nolint:lll

	testInterimDID         = "did:orb:uAAA:suffix"
	testInterimDIDWithHint = "did:orb:https:domain.com:uAAA:suffix"
	invalidTestDID         = "did:webcas"

	createDocumentStore = "create-document"

	firstCID  = "did:orb:first-cid:suffix"
	secondCID = "did:orb:second-cid:suffix"

	domain             = "https://domain.com"
	anchorOriginDomain = "https://anchor-origin.domain.com"

	recoveryCommitment = "recovery-commitment"
	updateCommitment   = "update-commitment"
)

func TestResolveHandler_Resolve(t *testing.T) {
	anchorGraph := &orbmocks.AnchorGraph{}
	anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}}}, nil)

	const localID = "local-id"

	t.Run("success - without document create store(canonical did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - unpublished operations provided from anchor origin (documents match)", func(t *testing.T) { //nolint:lll
		doc := make(document.Document)
		doc["id"] = localID

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturnsOnCall(0, localResolutionResult, nil)

		discovery := &mocks.Discovery{}

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

		localResolutionResultWithOps := &document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata}
		coreHandler.ResolveDocumentReturnsOnCall(1, localResolutionResultWithOps, nil)

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - published operations provided from anchor origin (documents match)", func(t *testing.T) {
		doc := make(document.Document)
		doc["id"] = localID

		methodMetadata := make(map[string]interface{})
		localPublishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "create-ref", TransactionTime: 0},
		}
		methodMetadata[document.PublishedOperationsProperty] = localPublishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		localResolutionResult := &document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturnsOnCall(0, localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		anchorOriginMethodMetadata := make(map[string]interface{})
		anchorOriginPublishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "create-ref", TransactionTime: 0},
			{Type: operation.TypeUpdate, CanonicalReference: "update-ref", TransactionTime: 1},
		}
		anchorOriginMethodMetadata[document.PublishedOperationsProperty] = anchorOriginPublishedOps

		anchorOriginDocMetadata := make(document.Metadata)
		anchorOriginDocMetadata[document.MethodProperty] = anchorOriginMethodMetadata

		localResolutionResultWithOps := &document.ResolutionResult{Document: doc, DocumentMetadata: anchorOriginDocMetadata}
		coreHandler.ResolveDocumentReturnsOnCall(1, localResolutionResultWithOps, nil)

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: anchorOriginDocMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - no local published operations provided (not configured)", func(t *testing.T) {
		doc := make(document.Document)
		doc["id"] = localID

		methodMetadata := make(map[string]interface{})

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		localResolutionResult := &document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturnsOnCall(0, localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		anchorOriginMethodMetadata := make(map[string]interface{})
		anchorOriginPublishedOps := []metadata.PublishedOperation{
			{Type: operation.TypeCreate, CanonicalReference: "create-ref", TransactionTime: 0},
			{Type: operation.TypeUpdate, CanonicalReference: "update-ref", TransactionTime: 1},
		}
		anchorOriginMethodMetadata[document.PublishedOperationsProperty] = anchorOriginPublishedOps

		anchorOriginDocMetadata := make(document.Metadata)
		anchorOriginDocMetadata[document.MethodProperty] = anchorOriginMethodMetadata

		localResolutionResultWithOps := &document.ResolutionResult{Document: doc, DocumentMetadata: anchorOriginDocMetadata}
		coreHandler.ResolveDocumentReturnsOnCall(1, localResolutionResultWithOps, nil)

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: anchorOriginDocMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - unpublished operations not provided from anchor origin (return local)", func(t *testing.T) { //nolint:lll
		doc := make(document.Document)
		doc["id"] = localID

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        anchorOriginDomain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", anchorOriginDomain)},
			}, nil)

		methodMetadata := make(map[string]interface{})

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         doc,
				DocumentMetadata: docMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - unpublished operations provided from anchor origin(documents don't match)", func(t *testing.T) { //nolint:lll
		doc := make(document.Document)
		doc["id"] = localID

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(localResolutionResult, nil)

		discovery := &mocks.Discovery{}

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

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         document.Document{},
				DocumentMetadata: docMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - unpublished operations provided from anchor origin(local resolve fails)", func(t *testing.T) { //nolint:lll
		doc := make(document.Document)
		doc["id"] = localID

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturnsOnCall(0, localResolutionResult, nil)
		coreHandler.ResolveDocumentReturnsOnCall(1, nil, fmt.Errorf("local resolve call with ops fails"))

		discovery := &mocks.Discovery{}

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

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document:         document.Document{},
				DocumentMetadata: docMetadata,
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - remote resolution enabled(anchor origin and domain are the same, return local result)", func(t *testing.T) { //nolint:lll
		doc := make(document.Document)
		doc["id"] = localID

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        domain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", domain)},
			}, nil)

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(&document.ResolutionResult{}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - remote resolution enabled(error from remote, return local)", func(t *testing.T) {
		doc := make(document.Document)
		doc["id"] = "local"

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        domain,
				ResolutionEndpoints: []string{fmt.Sprintf("%s/identifiers", domain)},
			}, nil)

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(nil, fmt.Errorf("remote resolver error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("success - remote resolution enabled(error from endpoint, return local)", func(t *testing.T) {
		doc := make(document.Document)
		doc["id"] = "local"

		localResolutionResult := &document.ResolutionResult{Document: doc}

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(localResolutionResult, nil)

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(nil, fmt.Errorf("endpoint error"))

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(
			&document.ResolutionResult{
				Document: make(document.Document),
			}, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, localResolutionResult.Document, response.Document)
	})

	t.Run("error - remote resolution enabled(error from local resolver, return error)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, fmt.Errorf("local resolver error"))

		discovery := &mocks.Discovery{}

		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(
			&models.Endpoint{
				AnchorOrigin:        "domain.com",
				ResolutionEndpoints: []string{"domain.com/identifiers"},
			}, nil)

		remoteResolutionResult := &document.ResolutionResult{Document: make(document.Document)}

		remoteResolver := &mocks.RemoteResolver{}
		remoteResolver.ResolveDocumentFromResolutionEndpointsReturns(remoteResolutionResult, nil)

		handler := NewResolveHandler(testNS, coreHandler, discovery,
			domain, endpointClient, remoteResolver, anchorGraph,
			&orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithEnableResolutionFromAnchorOrigin(true))

		response, err := handler.ResolveDocument(testDID)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "local resolver error")
	})

	t.Run("success - without document create store(interim did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - with create document store(canonical did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - with create document store(did with hashlink)", func(t *testing.T) {
		docMD := make(map[string]interface{})
		docMD[document.CanonicalIDProperty] = testDIDCanonical

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{DocumentMetadata: docMD}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument("did:orb:hl:hash:suffix")
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "hashlink[hl:hash] is not a valid multihash")
	})

	t.Run("success - with create document store(interim did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		doc := make(document.Document)
		doc[document.IDProperty] = testInterimDID

		rrBytes, err := json.Marshal(&document.ResolutionResult{Document: doc})
		require.NoError(t, err)

		err = store.Put("suffix", rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)

		// since did is found in operation store it will be deleted from create operation store
		_, err = store.Get("suffix")
		require.Equal(t, err, storage.ErrDataNotFound)
	})

	t.Run("success - with create document store(interim did with hint)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		doc := make(document.Document)
		doc[document.IDProperty] = testInterimDID

		rrBytes, err := json.Marshal(&document.ResolutionResult{Document: doc})
		require.NoError(t, err)

		err = store.Put("suffix", rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument(testInterimDIDWithHint)
		require.NoError(t, err)
		require.NotNil(t, response)

		// since did is found in operation store it will be deleted from create operation store
		_, err = store.Get("suffix")
		require.Equal(t, err, storage.ErrDataNotFound)
	})

	t.Run("success - invalid did passed in for deletion from create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument("did:orb:uAAA")
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - did not found in operation store and did found in create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		doc := make(document.Document)
		doc[document.IDProperty] = testInterimDID

		rrBytes, err := json.Marshal(&document.ResolutionResult{Document: doc})
		require.NoError(t, err)

		suffix, err := util.GetSuffix(testInterimDID)
		require.NoError(t, err)

		err = store.Put(suffix, rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, testInterimDID, response.Document["id"])
	})

	t.Run("success - interim did with hint resolved from create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		doc := make(document.Document)
		doc[document.IDProperty] = testInterimDID

		rrBytes, err := json.Marshal(&document.ResolutionResult{Document: doc})
		require.NoError(t, err)

		suffix, err := util.GetSuffix(testInterimDID)
		require.NoError(t, err)

		err = store.Put(suffix, rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDIDWithHint)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, testInterimDID, response.Document["id"])
	})

	t.Run("success - unable to resolve interim did from create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		doc := make(document.Document)
		doc[document.IDProperty] = testInterimDID

		rrBytes, err := json.Marshal(&document.ResolutionResult{Document: doc})
		require.NoError(t, err)

		suffix, err := util.GetSuffix(testInterimDID)
		require.NoError(t, err)

		err = store.Put(suffix, rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument("did:orb:uAAA")
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (invalid did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did", coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(invalidTestDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - anchor graph error", func(t *testing.T) {
		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = secondCID

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{DocumentMetadata: docMetadata}, nil)

		discovery := &mocks.Discovery{}

		anchorGraphWithErr := &orbmocks.AnchorGraph{}
		anchorGraphWithErr.GetDidAnchorsReturns(nil, fmt.Errorf("anchor graph error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraphWithErr,
			&orbmocks.MetricsProvider{}, WithUnpublishedDIDLabel(testLabel))

		response, err := handler.ResolveDocument(firstCID)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "anchor graph error")
	})

	t.Run("error - not found error (did without hint)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - did not found error in operation store and did not found in create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - did not found in operation store, marshal error from create document store", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		err = store.Put(testInterimDID, []byte(""))
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - create document store error (original not found error returned)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		store := &storemocks.Store{}
		store.GetReturns(nil, fmt.Errorf("create document store error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("success - create document store error during delete", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		store := &storemocks.Store{}
		store.DeleteReturns(fmt.Errorf("delete from document store error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - not found error (invalid did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did", coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(invalidTestDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (did with cid)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (wrong namespace)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", coreHandler, discovery, "", nil, nil, anchorGraph,
			&orbmocks.MetricsProvider{}, WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (check aliases)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", coreHandler, discovery, "", nil, nil, anchorGraph,
			&orbmocks.MetricsProvider{}, WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - discovery error (logs warning)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}
		discovery.RequestDiscoveryReturns(errors.New("discovery error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("internal error"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - with create document store(did with invalid hashlink)", func(t *testing.T) {
		docMD := make(map[string]interface{})
		docMD[document.CanonicalIDProperty] = testDIDCanonical

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{DocumentMetadata: docMD}, nil)

		discovery := &mocks.Discovery{}

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{},
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithHL)
		require.NoError(t, err)
		require.NotNil(t, response)
	})
}

func TestResolveHandler_VerifyCID(t *testing.T) {
	t.Run("success - CID in DID matches resolved document CID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:cid:suffix"

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.NoError(t, err)
	})

	t.Run("success - CID in DID matches document's previous CID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{
			{Info: &vocab.AnchorEventType{}, CID: "first-cid"},
			{Info: &vocab.AnchorEventType{}, CID: "second-cid"},
		}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = secondCID

		err := handler.verifyCID("did:orb:first-cid:suffix", &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.NoError(t, err)
	})

	t.Run("success - no canonical id (ignore)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		err := handler.verifyCID(testDID, &document.ResolutionResult{})
		require.NoError(t, err)
	})

	t.Run("error - canonical ID not a string", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = []string{"did:orb:cid:suffix"}

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected interface '[]string' for canonicalId")
	})

	t.Run("error - canonical ID invalid (wrong number of parts)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:suffix"

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "CID from resolved document: invalid number of parts[3] for Orb identifier")
	})

	t.Run("error - DID invalid (wrong number of parts)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:cid:suffix"

		err := handler.verifyCID("suffix", &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "CID from ID: invalid number of parts[1] for Orb identifier")
	})

	t.Run("error - resolved create document CID doesn't matches CID in DID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &vocab.AnchorEventType{}, CID: "cid2"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:cid2:suffix"

		err := handler.verifyCID("did:orb:cid1:suffix", &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Equal(t, ErrDocumentNotFound, err)
	})

	t.Run("error - CID in DID doesn't match any of document's previous CIDs", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{
			{Info: &vocab.AnchorEventType{}, CID: "first-cid"},
			{Info: &vocab.AnchorEventType{}, CID: "second-cid"},
		}, nil)

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:second-cid:suffix"

		err := handler.verifyCID("did:orb:third-cid:suffix", &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Equal(t, ErrDocumentNotFound, err)
	})

	t.Run("error - anchor graph error", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns(nil, fmt.Errorf("anchor graph error"))

		handler := NewResolveHandler(testNS, nil, nil, "", nil, nil, anchorGraph, &orbmocks.MetricsProvider{})

		docMetadata := make(document.Metadata)
		docMetadata[document.CanonicalIDProperty] = "did:orb:second-cid:suffix"

		err := handler.verifyCID("did:orb:third-cid:suffix", &document.ResolutionResult{DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor graph error")
	})
}

func TestCheckResponses(t *testing.T) {
	doc := make(document.Document)

	methodMetadata := make(map[string]interface{})
	methodMetadata[document.RecoveryCommitmentProperty] = recoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = updateCommitment

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata

	t.Run("success", func(t *testing.T) {
		err := checkResponses(&document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata},
			&document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata})
		require.NoError(t, err)
	})

	t.Run("error - unable to check commitments", func(t *testing.T) {
		err := checkResponses(&document.ResolutionResult{Document: doc}, &document.ResolutionResult{Document: doc})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing document metadata")
	})
}

func TestEqualDocuments(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		err := equalDocuments(make(document.Document), make(document.Document))
		require.NoError(t, err)
	})
	t.Run("error - marshal anchor origin document", func(t *testing.T) {
		err := equalDocuments(nil, make(document.Document))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal canonical anchor origin document")
	})
	t.Run("error - marshal local document", func(t *testing.T) {
		err := equalDocuments(make(document.Document), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal canonical local document")
	})
}

func TestEqualCommitments(t *testing.T) {
	methodMetadata := make(map[string]interface{})
	methodMetadata[document.RecoveryCommitmentProperty] = recoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = updateCommitment

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata

	t.Run("success", func(t *testing.T) {
		err := equalCommitments(docMetadata, docMetadata)
		require.NoError(t, err)
	})

	t.Run("error - anchor origin missing method metadata", func(t *testing.T) {
		err := equalCommitments(make(document.Metadata), docMetadata)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get anchor origin metadata: missing method metadata")
	})

	t.Run("error - local missing method metadata", func(t *testing.T) {
		err := equalCommitments(docMetadata, make(document.Metadata))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get local metadata: missing method metadata")
	})

	t.Run("error - missing update commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'updateCommitment' in local method metadata")
	})

	t.Run("error - missing recovery commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'recoveryCommitment' in local method metadata")
	})

	t.Run("error - different commitments (update)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = "invalid-commitment"

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor origin and local update commitments don't match")
	})

	t.Run("error - different commitments (recovery)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = "invalid-commitment"
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor origin and local recovery commitments don't match")
	})
}

func TestGetOperations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		unpubOps, pubOps := getOperations("did", docMetadata)
		require.Equal(t, len(unpublishedOps), len(unpubOps))
		require.Equal(t, len(publishedOps), len(pubOps))
	})

	t.Run("no operations - wrong metadata type", func(t *testing.T) {
		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = "invalid-type"

		unpubOps, pubOps := getOperations("did", docMetadata)
		require.Empty(t, unpubOps)
		require.Empty(t, pubOps)
	})

	t.Run("no operations - empty metadata", func(t *testing.T) {
		unpublishedOps, publishedOps := getOperations("did", make(document.Metadata))
		require.Empty(t, unpublishedOps)
		require.Empty(t, publishedOps)
	})
}
