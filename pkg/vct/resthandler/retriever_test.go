/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

func TestNewRetriever(t *testing.T) {
	configStore, err := mem.NewProvider().OpenStore(configStoreName)
	require.NoError(t, err)

	logConfigurator := NewRetriever(configStore)
	require.NotNil(t, logConfigurator)
	require.Equal(t, endpoint, logConfigurator.Path())
	require.Equal(t, http.MethodGet, logConfigurator.Method())
	require.NotNil(t, logConfigurator.Handler())
}

func TestLogRetriever_Handler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		testLogBytes, err := json.Marshal(&logConfig{URL: testLogURL})
		require.NoError(t, err)

		require.NoError(t, configStore.Put(logURLKey, testLogBytes))

		logRetriever := NewRetriever(configStore)
		require.NotNil(t, logRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		logRetriever.handle(rw, req)

		result := rw.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, result.Body.Close())
		require.NoError(t, err)
		require.Equal(t, testLogURL, string(respBytes))

		require.Equal(t, "text/plain", result.Header.Get("Content-Type"))
	})

	t.Run("404 - NotFound", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logRetriever := NewRetriever(configStore)
		require.NotNil(t, logRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		logRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - config store error", func(t *testing.T) {
		configStore := &storemocks.Store{}
		configStore.GetReturns(nil, errors.New("get error"))

		logRetriever := NewRetriever(configStore)
		require.NotNil(t, logRetriever)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		logRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		configStore := &storemocks.Store{}

		logRetriever := NewRetriever(configStore)
		require.NotNil(t, logRetriever)

		errExpected := errors.New("injected unmarshal error")

		logRetriever.unmarshal = func(bytes []byte, i interface{}) error {
			return errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, http.NoBody)

		logRetriever.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
