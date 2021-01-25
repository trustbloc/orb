/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidtxnref

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemDidTxnRef_Add(t *testing.T) {
	refs := New()

	err := refs.Add("did", "cid")
	require.NoError(t, err)
}

func TestMemDidTxnRef_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		refs := New()

		err := refs.Add("did", "cid")
		require.NoError(t, err)

		didTxnRefs, err := refs.Get("did")
		require.NoError(t, err)
		require.Equal(t, didTxnRefs, []string{"cid"})
	})

	t.Run("error - did transaction references not found", func(t *testing.T) {
		refs := New()

		didTxnRefs, err := refs.Get("non-existent")
		require.Error(t, err)
		require.Nil(t, didTxnRefs)
	})
}
