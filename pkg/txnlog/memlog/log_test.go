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

	txnInfo := txnlog.Info{
		AnchorString:        "anchor",
		Namespace:           "namespace",
		ProtocolGenesisTime: 100,
	}

	txn, err := log.Append(txnInfo)
	require.NoError(t, err)
	require.NotNil(t, txn)
}
