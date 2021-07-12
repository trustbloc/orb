/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLedgerType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		lt := &LedgerType{}

		dur, err := lt.CacheLifetime()
		require.NoError(t, err)
		require.NotNil(t, dur)
	})
}
