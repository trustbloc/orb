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

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/document/updatehandler/mocks"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

const (
	testNS = "did:orb"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := New(&mocks.Processor{}, &orbmocks.MetricsProvider{})
		require.NotNil(t, handler)
	})
}

func TestUpdateHandler_Namespace(t *testing.T) {
	t.Run("success - created documents storage enabled(create)", func(t *testing.T) {
		coreProcessor := &mocks.Processor{}
		coreProcessor.NamespaceReturns(testNS)

		handler := New(coreProcessor, &orbmocks.MetricsProvider{})

		ns := handler.Namespace()
		require.Equal(t, testNS, ns)
	})
}

func TestUpdateHandler_ProcessOperation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc := make(document.Document)
		doc[document.IDProperty] = "did:orb:uAAA:someID"

		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(&document.ResolutionResult{Document: doc}, nil)

		handler := New(coreProcessor, &orbmocks.MetricsProvider{})

		response, err := handler.ProcessOperation(nil, 0)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - core processor error", func(t *testing.T) {
		coreProcessor := &mocks.Processor{}
		coreProcessor.ProcessOperationReturns(nil, fmt.Errorf("processor error"))

		handler := New(coreProcessor, &orbmocks.MetricsProvider{})

		response, err := handler.ProcessOperation(nil, 0)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "processor error")
	})
}
