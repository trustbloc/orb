/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
)

const testLogModuleName = "test"

var testLogger = log.New(testLogModuleName)

func TestSetLogLevel(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(testLogger, "debug")

		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level", func(t *testing.T) {
		resetLoggingLevels()

		SetDefaultLogLevel(testLogger, "mango")

		// Should remain unchanged
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func resetLoggingLevels() {
	log.SetLevel("", log.INFO)
}
