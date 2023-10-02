/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/witness/policy/mocks"
)

func TestNewRetriever(t *testing.T) {
	policyStore := &mocks.PolicyStore{}

	policyConfigurator := NewRetriever(policyStore)
	require.NotNil(t, policyConfigurator)
	require.Equal(t, endpoint, policyConfigurator.Path())
	require.Equal(t, http.MethodGet, policyConfigurator.Method())
	require.NotNil(t, policyConfigurator.Handler())
}

func TestPolicyRetriever_Handler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}
		policyStore.GetPolicyReturns(testPolicy, nil)

		policyRetriever := NewRetriever(policyStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		policyRetriever.handle(rw, req)

		result := rw.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, result.Body.Close())
		require.NoError(t, err)
		require.Equal(t, testPolicy, string(respBytes))

		require.Equal(t, "text/plain", result.Header.Get("Content-Type"))
	})

	t.Run("404 - NotFound", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}
		policyStore.GetPolicyReturns("", storage.ErrDataNotFound)

		policyRetriever := NewRetriever(policyStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		policyRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - config store error", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}
		policyStore.GetPolicyReturns("", errors.New("get error"))

		policyRetriever := NewRetriever(policyStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		policyRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
