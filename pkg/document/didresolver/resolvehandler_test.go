/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didresolver

//go:generate counterfeiter -o ./mocks/webresolver.gen.go --fake-name WebResolver . webResolver
//go:generate counterfeiter -o ./mocks/orbresolver.gen.go --fake-name OrbResolver . orbResolver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/document/didresolver/mocks"
)

func TestResolveHandler_Resolve(t *testing.T) {
	t.Run("success - orb document", func(t *testing.T) {
		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		webResolver := &mocks.WebResolver{}
		webResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		handler := NewResolveHandler(orbResolver, webResolver)

		response, err := handler.ResolveDocument("did:orb:suffix")
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - web document", func(t *testing.T) {
		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		webResolver := &mocks.WebResolver{}
		webResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		handler := NewResolveHandler(orbResolver, webResolver)

		response, err := handler.ResolveDocument("did:web:suffix")
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - did method not supported", func(t *testing.T) {
		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		webResolver := &mocks.WebResolver{}
		webResolver.ResolveDocumentReturns(&document.ResolutionResult{}, nil)

		handler := NewResolveHandler(orbResolver, webResolver)

		response, err := handler.ResolveDocument("did:other:suffix")
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "did method not supported")
	})
}
