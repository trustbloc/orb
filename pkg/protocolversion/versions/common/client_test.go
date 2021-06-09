/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestClientVersion(t *testing.T) {
	p := &ClientVersion{
		VersionStr: "1.1",
		P: protocol.Protocol{
			GenesisTime: 1000,
		},
		OpProvider: &coremocks.OperationProvider{},
	}

	require.Equal(t, p.VersionStr, p.Version())
	require.Equal(t, p.P, p.Protocol())
	require.Equal(t, p.OpProvider, p.OperationProvider())
}
