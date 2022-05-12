/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitorcmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAcceptListCmd(t *testing.T) {
	t.Run("test missing subcommand", func(t *testing.T) {
		err := GetCmd().Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting subcommand activate, deactivate, or get")
	})
}
