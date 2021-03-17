/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAnchorData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ad, err := ParseAnchorString("101.coreIndexURI")
		require.NoError(t, err)
		require.NotNil(t, ad)

		require.Equal(t, ad.OperationCount, uint64(101))
		require.Equal(t, ad.CoreIndexFileURI, "coreIndexURI")

		require.Equal(t, "101.coreIndexURI", ad.GetAnchorString())
	})

	t.Run("error - invalid number of parts", func(t *testing.T) {
		ad, err := ParseAnchorString("1.coreIndexURI.other")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "expecting [2] parts, got [3] parts")
	})

	t.Run("error - invalid number of operations", func(t *testing.T) {
		ad, err := ParseAnchorString("abc.coreIndexURI")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})

	t.Run("error - invalid number of operations starts with 0", func(t *testing.T) {
		ad, err := ParseAnchorString("01.coreIndexURI")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})

	t.Run("error - number of operations is negative", func(t *testing.T) {
		ad, err := ParseAnchorString("-1.coreIndexURI")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})
}
