/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blockchain

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/txnlog/memlog"
)

const (
	namespace = "did:sidetree"
)

func TestNew(t *testing.T) {
	var txnCh chan []txn.SidetreeTxn

	c := New(namespace, memlog.New(), txnCh)
	require.NotNil(t, c)
}

func TestClient_WriteAnchor(t *testing.T) {
	txnCh := make(chan []txn.SidetreeTxn, 100)

	c := New(namespace, memlog.New(), txnCh)

	err := c.WriteAnchor("anchor", 100)
	require.NoError(t, err)
}

func TestClient_Read(t *testing.T) {
	txnCh := make(chan []txn.SidetreeTxn, 100)

	c := New(namespace, memlog.New(), txnCh)

	// get all entries
	more, entries := c.Read(-1)
	require.False(t, more)
	require.Empty(t, entries)
}
