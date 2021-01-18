/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txngraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	log := New(mocks.NewMockCasClient(nil))
	require.NotNil(t, log)
}

func TestGraph_Add(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil))

		txnInfo := &Node{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		cid, err := graph.Add(txnInfo)
		require.NoError(t, err)
		require.NotNil(t, cid)
	})
}

func TestGraph_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil))

		txnInfo := &Node{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		txnCID, err := graph.Add(txnInfo)
		require.NoError(t, err)
		require.NotNil(t, txnCID)

		txnNode, err := graph.Read(txnCID)
		require.NoError(t, err)
		require.Equal(t, txnInfo, txnNode)
	})

	t.Run("error - transaction (cid) not found", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil))

		txnNode, err := graph.Read("non-existent")
		require.Error(t, err)
		require.Nil(t, txnNode)
	})
}
