/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package updatehandler

//nolint:lll
//go:generate counterfeiter -o ./mocks/dochandler.gen.go --fake-name Processor github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler.Processor

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/document/updatehandler/mocks"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testNS = "did:orb"

	createDocumentStore = "create-document"
)

func TestNew(t *testing.T) {
	t.Run("success - created documents storage enabled", func(t *testing.T) {
		handler := New(&mocks.Processor{}, WithCreateDocumentStore(&storemocks.Store{}))
		require.NotNil(t, handler)
		require.True(t, handler.createDocumentStoreEnabled)
	})

	t.Run("success - created documents storage disabled", func(t *testing.T) {
		handler := New(&mocks.Processor{})
		require.NotNil(t, handler)
		require.False(t, handler.createDocumentStoreEnabled)
	})
}

func TestUpdateHandler_Namespace(t *testing.T) {
	t.Run("success - created documents storage enabled(create)", func(t *testing.T) {
		coreProcessor := &mocks.Processor{}
		coreProcessor.NamespaceReturns(testNS)

		handler := New(coreProcessor)

		ns := handler.Namespace()
		require.Equal(t, testNS, ns)
	})
}

func TestUpdateHandler_ProcessOperation(t *testing.T) {
	t.Run("success - created documents storage enabled(create)", func(t *testing.T) {
		doc := make(document.Document)
		doc[document.IDProperty] = "testID"

		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(&document.ResolutionResult{Document: doc}, nil)

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := New(coreProcessor, WithCreateDocumentStore(store))

		response, err := handler.ProcessOperation(nil, 0)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("success - created documents storage enabled (update/recover/deactivate)", func(t *testing.T) {
		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(nil, nil)

		store, err := mem.NewProvider().OpenStore(createDocumentStore)
		require.NoError(t, err)

		handler := New(coreProcessor, WithCreateDocumentStore(store))

		response, err := handler.ProcessOperation(nil, 0)
		require.NoError(t, err)
		require.Nil(t, response)
	})

	t.Run("success - created documents storage disabled(create)", func(t *testing.T) {
		doc := make(document.Document)
		doc[document.IDProperty] = "someID"

		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(&document.ResolutionResult{Document: doc}, nil)

		handler := New(coreProcessor)

		response, err := handler.ProcessOperation(nil, 0)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - core processor error", func(t *testing.T) {
		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(nil, fmt.Errorf("processor error"))

		handler := New(coreProcessor)

		response, err := handler.ProcessOperation(nil, 0)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "processor error")
	})

	t.Run("error - document store error", func(t *testing.T) {
		doc := make(document.Document)
		doc[document.IDProperty] = "testID"

		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(&document.ResolutionResult{Document: doc}, nil)

		store := &storemocks.Store{}
		store.PutReturns(fmt.Errorf("put error"))

		handler := New(coreProcessor, WithCreateDocumentStore(store))

		response, err := handler.ProcessOperation(nil, 0)
		require.NoError(t, err)
		require.NotNil(t, response)
	})
}
