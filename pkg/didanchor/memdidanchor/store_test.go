/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidanchor

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/didanchor"
)

const (
	testSuffix = "suffix"
	testCID    = "cid"
)

func TestDidAnchor_PutBulk(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)
	})
}

func TestDidAnchor_GetBulk(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)

		anchors, err := refs.GetBulk([]string{testSuffix})
		require.NoError(t, err)
		require.Equal(t, anchors, []string{testCID})
	})

	t.Run("success - did anchor not found", func(t *testing.T) {
		refs := New()

		anchors, err := refs.GetBulk([]string{"non-existent"})
		require.NoError(t, err)
		require.Equal(t, "", anchors[0])
	})
}

func TestDidAnchor_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)

		anchor, err := refs.Get(testSuffix)
		require.NoError(t, err)
		require.Equal(t, anchor, testCID)
	})

	t.Run("error - did anchor not found", func(t *testing.T) {
		refs := New()

		anchor, err := refs.Get("non-existent")
		require.Error(t, err)
		require.Empty(t, anchor)
		require.Equal(t, err, didanchor.ErrDataNotFound)
	})
}
