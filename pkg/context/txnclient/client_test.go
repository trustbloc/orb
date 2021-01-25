/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnclient

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/didtxnref/memdidtxnref"
	"github.com/trustbloc/orb/pkg/txngraph"
)

const (
	namespace = "did:sidetree"
)

func TestNew(t *testing.T) {
	var txnCh chan []string

	c := New(namespace, txngraph.New(nil), memdidtxnref.New(), txnCh)
	require.NotNil(t, c)
}

func TestClient_WriteAnchor(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		const testDID = "did:method:abc"

		didTxns := memdidtxnref.New()
		err := didTxns.Add(testDID, "cid")
		require.NoError(t, err)

		c := New(namespace, txngraph.New(mocks.NewMockCasClient(nil)), didTxns, txnCh)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID}}, 1)
		require.NoError(t, err)
	})

	t.Run("error - cas error", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		const testDID = "did:method:abc"

		didTxns := memdidtxnref.New()
		err := didTxns.Add(testDID, "cid")
		require.NoError(t, err)

		casErr := errors.New("CAS Error")
		c := New(namespace, txngraph.New(mocks.NewMockCasClient(casErr)), didTxns, txnCh)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID}}, 1)
		require.Equal(t, err, casErr)
	})
}

func TestClient_Read(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		c := New(namespace, txngraph.New(mocks.NewMockCasClient(nil)), memdidtxnref.New(), txnCh)

		more, entries := c.Read(-1)
		require.False(t, more)
		require.Empty(t, entries)
	})
}
