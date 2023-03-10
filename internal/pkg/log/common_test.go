/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
)

func TestCommonLogs(t *testing.T) {
	const module = "test_module"

	t.Run("InvalidParameterValue", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := log.New(module,
			log.WithStdErr(stdErr),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		InvalidParameterValue(logger, "param1", errors.New("invalid integer"))

		t.Logf(stdErr.String())

		require.Contains(t, stdErr.Buffer.String(), `Invalid parameter value`)
		require.Contains(t, stdErr.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdErr.Buffer.String(), `"parameter": "param1"`)
		require.Contains(t, stdErr.Buffer.String(), `"error": "invalid integer"`)
		require.Contains(t, stdErr.Buffer.String(), "log/common_test.go")
	})

	t.Run("CloseIteratorError", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module,
			log.WithStdOut(stdOut),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		CloseIteratorError(logger, errors.New("iterator error"))

		require.Contains(t, stdOut.Buffer.String(), `Error closing iterator`)
		require.Contains(t, stdOut.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdOut.Buffer.String(), `"error": "iterator error"`)
		require.Contains(t, stdOut.Buffer.String(), "log/common_test.go")
	})

	t.Run("CloseResponseBodyError", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module,
			log.WithStdOut(stdOut),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		CloseResponseBodyError(logger, errors.New("response body error"))

		require.Contains(t, stdOut.Buffer.String(), `Error closing response body`)
		require.Contains(t, stdOut.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdOut.Buffer.String(), `"error": "response body error"`)
		require.Contains(t, stdOut.Buffer.String(), "log/common_test.go")
	})

	t.Run("WriteResponseBodyError", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := log.New(module,
			log.WithStdErr(stdErr),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		WriteResponseBodyError(logger, errors.New("response body error"))

		require.Contains(t, stdErr.Buffer.String(), `Error writing response body`)
		require.Contains(t, stdErr.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdErr.Buffer.String(), `"error": "response body error"`)
		require.Contains(t, stdErr.Buffer.String(), "log/common_test.go")
	})

	t.Run("ReadRequestBodyError", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := log.New(module,
			log.WithStdErr(stdErr),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		ReadRequestBodyError(logger, errors.New("request body error"))

		require.Contains(t, stdErr.Buffer.String(), `Error reading request body`)
		require.Contains(t, stdErr.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdErr.Buffer.String(), `"error": "request body error"`)
		require.Contains(t, stdErr.Buffer.String(), "log/common_test.go")
	})

	t.Run("WroteResponse", func(t *testing.T) {
		log.SetLevel(module, log.DEBUG)

		stdOut := newMockWriter()

		logger := log.New(module,
			log.WithStdOut(stdOut),
			log.WithFields(WithServiceName("myservice")),
			log.WithEncoding(log.Console),
		)

		WroteResponse(logger, []byte("some response"))

		require.Contains(t, stdOut.Buffer.String(), `Wrote response`)
		require.Contains(t, stdOut.Buffer.String(), `"service": "myservice"`)
		require.Contains(t, stdOut.Buffer.String(), `"response": "some response"`)
		require.Contains(t, stdOut.Buffer.String(), "log/common_test.go")
	})
}
