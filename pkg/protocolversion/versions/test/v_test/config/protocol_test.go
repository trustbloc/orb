/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetProtocolConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := GetProtocolConfig()
		require.Equal(t, uint(5000), cfg.MaxOperationCount)
	})
}
