/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

func TestNewRetriever(t *testing.T) {
	configStore, err := mem.NewProvider().OpenStore(configStoreName)
	require.NoError(t, err)

	policyConfigurator := NewRetriever(configStore)
	require.NotNil(t, policyConfigurator)
	require.Equal(t, endpoint, policyConfigurator.Path())
	require.Equal(t, http.MethodGet, policyConfigurator.Method())
	require.NotNil(t, policyConfigurator.Handler())
}

func TestPolicyRetriever_Handler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		testPolicyBytes, err := json.Marshal(testPolicy)
		require.NoError(t, err)

		require.NoError(t, configStore.Put(policy.WitnessPolicyKey, testPolicyBytes))

		policyRetriever := NewRetriever(configStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)

		policyRetriever.handle(rw, req)

		result := rw.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, result.Body.Close())
		require.NoError(t, err)
		require.Equal(t, testPolicy, string(respBytes))

		require.Equal(t, "text/plain", result.Header.Get("Content-Type"))
	})

	t.Run("404 - NotFound", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		policyRetriever := NewRetriever(configStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)

		policyRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - config store error", func(t *testing.T) {
		configStore := &storemocks.Store{}
		configStore.GetReturns(nil, errors.New("get error"))

		policyRetriever := NewRetriever(configStore)
		require.NotNil(t, policyRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)

		policyRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		configStore := &storemocks.Store{}

		policyRetriever := NewRetriever(configStore)
		require.NotNil(t, policyRetriever)

		errExpected := errors.New("injected unmarshal error")

		policyRetriever.unmarshal = func(bytes []byte, i interface{}) error {
			return errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)

		policyRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
