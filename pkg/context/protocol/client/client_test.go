/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	client := New(nil)
	require.NotNil(t, client)
}

func TestClient_Current(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &coremocks.ProtocolVersion{}
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	versions := []protocol.Version{v1_0, v0_1}

	client := New(versions)
	require.NotNil(t, client)

	p, err := client.Current()
	require.NoError(t, err)
	require.Equal(t, uint(10000), p.Protocol().MaxOperationCount)
}

func TestClient_Get(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &coremocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	versions := []protocol.Version{v1_0, v0_1}

	client := New(versions)
	require.NotNil(t, client)

	p, err := client.Get(0)
	require.NoError(t, err)
	require.Equal(t, uint(100), p.Protocol().MaxOperationCount)
	require.Equal(t, "0.1", p.Version())

	p, err = client.Get(1)
	require.NoError(t, err)
	require.Equal(t, uint(10000), p.Protocol().MaxOperationCount)
	require.Equal(t, "1.0", p.Version())

	p, err = client.Get(5)
	require.Error(t, err)
	require.Nil(t, p)
	require.Equal(t, err.Error(), "protocol parameters are not defined for version genesis time: 5")
}
