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

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testLogURL      = "https://vct.com/log"
	configStoreName = "orb-config"
)

func TestNew(t *testing.T) {
	configStore, err := mem.NewProvider().OpenStore(configStoreName)
	require.NoError(t, err)

	logConfigurator := New(configStore, &mockLogMonitorStore{})
	require.NotNil(t, logConfigurator)
	require.Equal(t, endpoint, logConfigurator.Path())
	require.Equal(t, http.MethodPost, logConfigurator.Method())
	require.NotNil(t, logConfigurator.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testLogURL))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("success - empty URL (equivalent to no log)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(""))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - reader error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, errReader(0))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - parse URL error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(":InvalidURL"))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - config store error", func(t *testing.T) {
		configStore := &storemocks.Store{}
		configStore.PutReturns(fmt.Errorf("put error"))

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testLogURL))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - marshal error", func(t *testing.T) {
		configStore := &storemocks.Store{}

		logConfigurator := New(configStore, &mockLogMonitorStore{})
		require.NotNil(t, logConfigurator)

		errExpected := errors.New("injected marshal error")

		logConfigurator.marshal = func(interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testLogURL))

		logConfigurator.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - log monitor store error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		logConfigurator := New(configStore, &mockLogMonitorStore{Err: fmt.Errorf("log monitor store error")})
		require.NotNil(t, logConfigurator)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testLogURL))

		logConfigurator.handle(rw, req)

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

type mockLogMonitorStore struct {
	Err error
}

func (m *mockLogMonitorStore) Activate(_ string) error {
	return m.Err
}
