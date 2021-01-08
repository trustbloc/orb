/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memlog

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/txnlog"
)

func TestNew(t *testing.T) {
	log := New()
	require.NotNil(t, log)
}

func TestLog_Append(t *testing.T) {
	log := New()

	txn := txnlog.Info{
		AnchorString:        "anchor",
		Namespace:           "namespace",
		ProtocolGenesisTime: 100,
	}

	err := log.Append(txn)
	require.NoError(t, err)
}

func TestLog_Read(t *testing.T) {
	log := New()

	err := log.Append(txnlog.Info{AnchorString: "first"})
	require.NoError(t, err)

	entries, err := log.Read(-1)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	err = log.Append(txnlog.Info{AnchorString: "second"})
	require.NoError(t, err)

	entries, err = log.Read(-1)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// get all entries since first transaction (index 0)
	entries, err = log.Read(0)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// get all entries since fifth transaction
	entries, err = log.Read(5)
	require.NoError(t, err)
	require.Len(t, entries, 0)
}
