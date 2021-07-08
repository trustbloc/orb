/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

//nolint:lll
//go:generate counterfeiter -o ./mocks/dochandler.gen.go --fake-name Resolver github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler.Resolver
//go:generate counterfeiter -o ./mocks/discovery.gen.go --fake-name Discovery . discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/document/resolvehandler/mocks"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testNS    = "did:orb"
	testLabel = "interim"

	testDID               = "did:orb:cid:suffix"
	testDIDWithCIDAndHint = "did:orb:webcas:domain.com:cid:suffix"
	testInterimDID        = "did:orb:interim:suffix"
	invalidTestDID        = "did:webcas"

	createDocumentStore = "create-document"

	firstCID  = "did:orb:first-cid:suffix"
	secondCID = "did:orb:second-cid:suffix"
)

func TestResolveHandler_Resolve(t *testing.T) {
	anchorGraph := &orbmocks.AnchorGraph{}
	anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}}}, nil)

	t.Run("success - without document create store(canonical did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph, WithUnpublishedDIDLabel(testLabel))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - without document create store(interim did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph, WithUnpublishedDIDLabel(testLabel))

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

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
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

		err = store.Put(testInterimDID, rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)

		// since did is found in operation store it will be deleted from create operation store
		_, err = store.Get(testInterimDID)
		require.Equal(t, err, storage.ErrDataNotFound)
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

		err = store.Put(testInterimDID, rrBytes)
		require.NoError(t, err)

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel),
			WithCreateDocumentStore(store),
			WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testInterimDID)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.Equal(t, testInterimDID, response.Document["id"])
	})

	t.Run("error - not found error (invalid did)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did", coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(invalidTestDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - anchor graph error", func(t *testing.T) {
		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = secondCID

		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{DocumentMetadata: metadata}, nil)

		discovery := &mocks.Discovery{}

		anchorGraphWithErr := &orbmocks.AnchorGraph{}
		anchorGraphWithErr.GetDidAnchorsReturns(nil, fmt.Errorf("anchor graph error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraphWithErr, WithUnpublishedDIDLabel(testLabel))

		response, err := handler.ResolveDocument(firstCID)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "anchor graph error")
	})

	t.Run("error - not found error (did without hint)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
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

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
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

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
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

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
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

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
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

		handler := NewResolveHandler("did", coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(invalidTestDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (did with cid)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (wrong namespace)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (check aliases)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - discovery error (logs warning)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}
		discovery.RequestDiscoveryReturns(errors.New("discovery error"))

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDIDWithCIDAndHint)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("internal error"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, coreHandler, discovery, anchorGraph,
			WithUnpublishedDIDLabel(testLabel), WithEnableDIDDiscovery(true))

		response, err := handler.ResolveDocument(testDID)
		require.Error(t, err)
		require.Nil(t, response)
	})
}

func TestResolveHandler_VerifyCID(t *testing.T) {
	t.Run("success - CID in DID matches resolved document CID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:cid:suffix"

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: metadata})
		require.NoError(t, err)
	})

	t.Run("success - CID in DID matches document's previous CID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{
			{Info: &verifiable.Credential{}, CID: "first-cid"},
			{Info: &verifiable.Credential{}, CID: "second-cid"},
		}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = secondCID

		err := handler.verifyCID("did:orb:first-cid:suffix", &document.ResolutionResult{DocumentMetadata: metadata})
		require.NoError(t, err)
	})

	t.Run("success - no canonical id (ignore)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		err := handler.verifyCID(testDID, &document.ResolutionResult{})
		require.NoError(t, err)
	})

	t.Run("error - canonical ID not a string", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = []string{"did:orb:cid:suffix"}

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected interface '[]string' for canonicalId")
	})

	t.Run("error - canonical ID invalid (wrong number of parts)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:suffix"

		err := handler.verifyCID(testDID, &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "CID from resolved document: invalid number of parts[3] for Orb identifier")
	})

	t.Run("error - DID invalid (wrong number of parts)", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:cid:suffix"

		err := handler.verifyCID("suffix", &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "CID from ID: invalid number of parts[1] for Orb identifier")
	})

	t.Run("error - resolved create document CID doesn't matches CID in DID", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}, CID: "cid2"}}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:cid2:suffix"

		err := handler.verifyCID("did:orb:cid1:suffix", &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Equal(t, ErrDocumentNotFound, err)
	})

	t.Run("error - CID in DID doesn't match any of document's previous CIDs", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{
			{Info: &verifiable.Credential{}, CID: "first-cid"},
			{Info: &verifiable.Credential{}, CID: "second-cid"},
		}, nil)

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:second-cid:suffix"

		err := handler.verifyCID("did:orb:third-cid:suffix", &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Equal(t, ErrDocumentNotFound, err)
	})

	t.Run("error - anchor graph error", func(t *testing.T) {
		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns(nil, fmt.Errorf("anchor graph error"))

		handler := NewResolveHandler(testNS, nil, nil, anchorGraph)

		metadata := make(document.Metadata)
		metadata[document.CanonicalIDProperty] = "did:orb:second-cid:suffix"

		err := handler.verifyCID("did:orb:third-cid:suffix", &document.ResolutionResult{DocumentMetadata: metadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor graph error")
	})
}
