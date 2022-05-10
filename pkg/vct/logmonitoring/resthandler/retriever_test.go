/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

func TestNewRetriever(t *testing.T) {
	handler := NewRetriever(&mockLogMonitorStore{})
	require.NotNil(t, handler)
	require.Equal(t, endpoint, handler.Path())
	require.Equal(t, http.MethodGet, handler.Method())
	require.NotNil(t, handler.Handler())
}

func TestLogRetriever(t *testing.T) {
	t.Run("success - default active", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{
			ActiveLogs: []*logmonitor.LogMonitor{
				{Log: "https://vct.com/log"},
				{Log: "https://other.com/log"},
			},
		})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.NoError(t, result.Body.Close())

		var resp logResponse

		err = json.Unmarshal(respBytes, &resp)
		require.NoError(t, err)
		require.Equal(t, 2, len(resp.Active))
	})

	t.Run("success - active logs", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{ActiveLogs: []*logmonitor.LogMonitor{{Log: "https://vct.com/log"}}})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=active", nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		var resp logResponse

		err = json.Unmarshal(respBytes, &resp)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Active))
	})

	t.Run("success - inactive logs", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{InactiveLogs: []*logmonitor.LogMonitor{{Log: "https://vct.com/log"}}})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=inactive", nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		var resp logResponse

		err = json.Unmarshal(respBytes, &resp)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Inactive))
	})

	t.Run("error - invalid status parameter", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{InactiveLogs: []*logmonitor.LogMonitor{{Log: "https://vct.com/log"}}})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=invalid", nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - no active logs found", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{Err: orberrors.ErrContentNotFound})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=active", nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(notFoundResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - no inactive logs found", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{Err: orberrors.ErrContentNotFound})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=inactive", nil)

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(notFoundResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})

	t.Run("error - marshal logs error", func(t *testing.T) {
		handler := NewRetriever(&mockLogMonitorStore{ActiveLogs: []*logmonitor.LogMonitor{{Log: "https://vct.com/log"}}})

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, endpoint+"?status=active", nil)

		errExpected := fmt.Errorf("injected unmarshal error")

		handler.marshal = func(i interface{}) ([]byte, error) {
			return nil, errExpected
		}

		handler.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(internalServerErrorResponse), respBytes)
		require.NoError(t, result.Body.Close())
	})
}
