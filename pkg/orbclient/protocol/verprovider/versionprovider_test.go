/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verprovider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	vp := New(nil)
	require.NotNil(t, vp)
}

func TestClientVersionProvider_Current(t *testing.T) {
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

	clientVerProvider := New(versions)
	require.NotNil(t, clientVerProvider)

	v, err := clientVerProvider.Current()
	require.NoError(t, err)
	require.Equal(t, uint(10000), v.Protocol().MaxOperationCount)
}

func TestClientVersionProvider_Get(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         500000,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &coremocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         10,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	versions := []protocol.Version{v1_0, v0_1}

	vp := New(versions)
	require.NotNil(t, vp)

	v, err := vp.Get(100)
	require.NoError(t, err)
	require.Equal(t, uint(100), v.Protocol().MaxOperationCount)
	require.Equal(t, "0.1", v.Version())

	v, err = vp.Get(500000)
	require.NoError(t, err)
	require.Equal(t, uint(10000), v.Protocol().MaxOperationCount)
	require.Equal(t, "1.0", v.Version())

	v, err = vp.Get(7000000)
	require.NoError(t, err)
	require.Equal(t, uint(10000), v.Protocol().MaxOperationCount)

	v, err = vp.Get(5)
	require.Error(t, err)
	require.Nil(t, v)
	require.Equal(t, err.Error(), "client version is not defined for version genesis time: 5")
}
