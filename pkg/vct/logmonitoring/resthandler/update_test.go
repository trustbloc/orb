/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

const (
	testPayload       = `{"activate": ["https://vct.com/log"], "deactivate": ["https://old.com/log"]}`
	activatePayload   = `{"activate": ["https://vct.com/log", "https://second.com/log"]}`
	deactivatePayload = `{"deactivate": ["https://vct.com/log", "https://second.com/log"]}`
)

func TestNew(t *testing.T) {
	handler := NewUpdateHandler(&mockLogMonitorStore{})
	require.NotNil(t, handler)
	require.Equal(t, endpoint, handler.Path())
	require.Equal(t, http.MethodPost, handler.Method())
	require.NotNil(t, handler.Handler())
}

func TestActivate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(activatePayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - reader error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, errReader(0))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(activatePayload))

		errExpected := fmt.Errorf("injected unmarshal error")

		handler.unmarshal = func(bytes []byte, i interface{}) error {
			return errExpected
		}

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - parse URL error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		invalidPayload := []byte(`{"activate": [":InvalidURL"]}`)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(invalidPayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - log monitor store error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{Err: fmt.Errorf("log monitor store error")})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(activatePayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})
}

func TestDeactivate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(deactivatePayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - reader error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, errReader(0))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - parse URL error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		invalidPayload := []byte(`{"deactivate": [":InvalidURL"]}`)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(invalidPayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(badRequestResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - log monitor store error", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{Err: fmt.Errorf("log monitor store error")})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(deactivatePayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})
}

func TestActivateAndDeactivate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := NewUpdateHandler(&mockLogMonitorStore{})
		require.NotNil(t, handler)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(testPayload))

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.Empty(t, respBytes)
		require.NoError(t, result.Body.Close())
	})
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("reader error")
}

type mockLogMonitorStore struct {
	Err          error
	ActiveLogs   []*logmonitor.LogMonitor
	InactiveLogs []*logmonitor.LogMonitor
}

func (m *mockLogMonitorStore) Activate(_ string) error {
	return m.Err
}

func (m *mockLogMonitorStore) Deactivate(_ string) error {
	return m.Err
}

func (m *mockLogMonitorStore) GetActiveLogs() ([]*logmonitor.LogMonitor, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.ActiveLogs, nil
}

func (m *mockLogMonitorStore) GetInactiveLogs() ([]*logmonitor.LogMonitor, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.InactiveLogs, nil
}
