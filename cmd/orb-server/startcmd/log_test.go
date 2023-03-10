/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

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

const testLogModuleName = "test"

var testLogger = log.New(testLogModuleName)

func TestSetLogLevel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		defer resetLoggingLevels(t)

		setLogLevels(testLogger, "debug")

		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})

	t.Run("Log spec -> Success", func(t *testing.T) {
		defer resetLoggingLevels(t)

		setLogLevels(testLogger, "module1=debug:module2=error:warning")

		require.Equal(t, log.WARNING, log.GetLevel(""))
		require.Equal(t, log.DEBUG, log.GetLevel("module1"))
		require.Equal(t, log.ERROR, log.GetLevel("module2"))
	})

	t.Run("Invalid log level", func(t *testing.T) {
		defer resetLoggingLevels(t)

		setLogLevels(testLogger, "mango")

		// Should remain unchanged
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestLogSpec(t *testing.T) {
	const logSpecURL = "https://example.com/services/logger"

	t.Run("Success", func(t *testing.T) {
		defer resetLoggingLevels(t)

		const spec = "module3=WARN:ERROR"

		hw := newLogSpecWriter()
		require.NotNil(t, hw.Handler())
		require.Equal(t, logSpecPath, hw.Path())
		require.Equal(t, http.MethodPost, hw.Method())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, logSpecURL, bytes.NewBuffer([]byte(spec)))

		hw.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())

		require.Equal(t, log.ERROR, log.GetLevel(""))
		require.Equal(t, log.WARNING, log.GetLevel("module3"))

		hr := newLogSpecReader()
		require.NotNil(t, hr.Handler())
		require.Equal(t, logSpecPath, hr.Path())
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
		h := newLogSpecWriter()
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

		h := newLogSpecWriter()
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

func resetLoggingLevels(t *testing.T) {
	t.Helper()

	log.SetDefaultLevel(log.INFO)
	log.SetLevel("module1", log.INFO)
	log.SetLevel("module2", log.INFO)
	log.SetLevel("module3", log.INFO)
}
