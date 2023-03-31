/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package loglevels

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
)

func TestLogLevels(t *testing.T) {
	const logSpecURL = "https://example.com/services/logger"

	t.Run("Success", func(t *testing.T) {
		defer func() {
			log.SetDefaultLevel(log.INFO)

			log.SetLevel("module1", log.INFO)
			log.SetLevel("module2", log.INFO)
			log.SetLevel("module3", log.INFO)
		}()

		const spec = "module3=WARN:ERROR"

		hw := NewWriteHandler()
		require.NotNil(t, hw.Handler())
		require.Equal(t, logLevelsPath, hw.Path())
		require.Equal(t, http.MethodPost, hw.Method())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, logSpecURL, bytes.NewBuffer([]byte(spec)))

		hw.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		require.Equal(t, log.ERROR, log.GetLevel(""))
		require.Equal(t, log.WARNING, log.GetLevel("module3"))

		hr := NewReadHandler()
		require.NotNil(t, hr.Handler())
		require.Equal(t, logLevelsPath, hr.Path())
		require.Equal(t, http.MethodGet, hr.Method())

		rw = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, logSpecURL, http.NoBody)

		hr.handleGet(rw, req)

		result = rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		response := string(respBytes)

		require.Contains(t, response, ":ERROR")
		require.Contains(t, response, "module3=WARN")
	})

	t.Run("Invalid spec -> error", func(t *testing.T) {
		h := NewWriteHandler()
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, logSpecURL, bytes.NewBuffer([]byte("module2:INFO")))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Read request error", func(t *testing.T) {
		errExpected := errors.New("injected read error")

		h := NewWriteHandler()
		require.NotNil(t, h.Handler())

		h.readAll = func(r io.Reader) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, logSpecURL, bytes.NewBuffer([]byte(`INFO`)))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
