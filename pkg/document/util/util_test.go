/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSuffix(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := GetSuffix("did:orb:uAAA:suffix")
		require.NoError(t, err)
		require.Equal(t, suffix, "suffix")
	})

	t.Run("error - invalid number of parts", func(t *testing.T) {
		suffix, err := GetSuffix("uAAA:suffix")
		require.Error(t, err)
		require.Empty(t, suffix)
		require.Contains(t, err.Error(), "invalid number of parts")
	})
}

func TestBetweenStrings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:uAAA:suffix", "did:orb:", ":suffix")
		require.NoError(t, err)
		require.Equal(t, str, "uAAA")
	})

	t.Run("error - doesn't contain first string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "first", "suffix")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(), "string 'did:orb:cid:suffix' doesn't contain first string 'first'")
	})

	t.Run("error - doesn't contain second string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "cid", "second")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(), "string 'did:orb:cid:suffix' doesn't contain second string 'second'")
	})

	t.Run("error - first string is after second string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "suffix", "did:orb")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(),
			"second string 'did:orb' is before first string 'suffix' in string 'did:orb:cid:suffix'")
	})
}
