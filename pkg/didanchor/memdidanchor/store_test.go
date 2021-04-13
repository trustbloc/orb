/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidanchor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDidAnchor_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.Put([]string{"did"}, "cid")
		require.NoError(t, err)
	})
}

func TestDidAnchor_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.Put([]string{"did"}, "cid")
		require.NoError(t, err)

		didTxnRefs, err := refs.Get([]string{"did"})
		require.NoError(t, err)
		require.Equal(t, didTxnRefs, []string{"cid"})
	})

	t.Run("success - did anchor reference not found", func(t *testing.T) {
		refs := New()

		anchors, err := refs.Get([]string{"non-existent"})
		require.NoError(t, err)
		require.Equal(t, "", anchors[0])
	})
}
