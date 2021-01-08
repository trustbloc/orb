/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blockchain

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/txnlog/memlog"
)

const (
	namespace = "did:orb"
)

func TestNew(t *testing.T) {
	c := New(namespace, memlog.New())
	require.NotNil(t, c)
}

func TestClient_WriteAnchor(t *testing.T) {
	c := New(namespace, memlog.New())

	err := c.WriteAnchor("anchor", 100)
	require.NoError(t, err)
}

func TestClient_Read(t *testing.T) {
	c := New(namespace, memlog.New())

	err := c.WriteAnchor("first", 100)
	require.NoError(t, err)

	// get all entries
	entries, err := c.Read(-1)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	err = c.WriteAnchor("second", 100)
	require.NoError(t, err)

	// get all entries
	entries, err = c.Read(-1)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// get all entries since first transaction (index 0)
	entries, err = c.Read(0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
