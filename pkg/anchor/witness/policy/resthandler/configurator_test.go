/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/witness/policy/mocks"
)

//go:generate counterfeiter -o ../mocks/policystore.gen.go --fake-name PolicyStore . policyStore

const testPolicy = "MinPercent(50,system) AND MinPercent(50,batch)"

func TestNew(t *testing.T) {
	policyStore := &mocks.PolicyStore{}

	policyConfigurator := New(policyStore)
	require.NotNil(t, policyConfigurator)
	require.Equal(t, endpoint, policyConfigurator.Path())
	require.Equal(t, http.MethodPost, policyConfigurator.Method())
	require.NotNil(t, policyConfigurator.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}

		policyConfigurator := New(policyStore)
		require.NotNil(t, policyConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testPolicy))

		policyConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - reader error", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}

		policyConfigurator := New(policyStore)
		require.NotNil(t, policyConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, errReader(0))

		policyConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - parse policy error", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}
		policyStore.PutPolicyReturns(errors.New("injected PutPolicy error"))

		policyConfigurator := New(policyStore)
		require.NotNil(t, policyConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString("InvalidPolicy"))

		policyConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - config store error", func(t *testing.T) {
		policyStore := &mocks.PolicyStore{}
		policyStore.PutPolicyReturns(fmt.Errorf("put error"))

		policyConfigurator := New(policyStore)
		require.NotNil(t, policyConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testPolicy))

		policyConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("reader error")
}
