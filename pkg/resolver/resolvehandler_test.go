/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

//nolint:lll
//go:generate counterfeiter -o ./mocks/dochandler.gen.go --fake-name Resolver github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler.Resolver
//go:generate counterfeiter -o ./mocks/discovery.gen.go --fake-name Discovery . discovery

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/resolver/mocks"
)

const (
	testNS         = "did:orb"
	testDID        = "did:orb:suffix"
	testDIDWithCID = "did:orb:cid:suffix"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDID)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - not found error (did without cid)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (did with cid)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDIDWithCID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (wrong namespace)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDIDWithCID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - not found error (check aliases)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler("did:not-orb", []string{testNS}, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDIDWithCID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - discovery error (logs warning)", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("not found"))

		discovery := &mocks.Discovery{}
		discovery.RequestDiscoveryReturns(errors.New("discovery error"))

		handler := NewResolveHandler(testNS, nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDIDWithCID)
		require.Error(t, err)
		require.Nil(t, response)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		coreHandler := &mocks.Resolver{}
		coreHandler.ResolveDocumentReturns(nil, errors.New("internal error"))

		discovery := &mocks.Discovery{}

		handler := NewResolveHandler(testNS, nil, coreHandler, discovery)

		response, err := handler.ResolveDocument(testDID)
		require.Error(t, err)
		require.Nil(t, response)
	})
}
