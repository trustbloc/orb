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
	t.Run("success - maximum operation count", func(t *testing.T) {
		cfg := GetProtocolConfig()
		require.Equal(t, uint(10000), cfg.MaxOperationCount)
	})

	t.Run("success - key algorithms", func(t *testing.T) {
		cfg := GetProtocolConfig()
		require.Equal(t, []string{"Ed25519", "P-256", "P-384", "secp256k1"}, cfg.KeyAlgorithms)
	})
}
