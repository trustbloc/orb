/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	svcprotocol "github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"
	svcmocks "github.com/trustbloc/sidetree-svc-go/pkg/mocks"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v1_0 := &svcmocks.ProtocolVersion{}
		v1_0.ProtocolReturns(protocol.Protocol{
			GenesisTime:         1,
			MultihashAlgorithms: []uint{18},
			MaxOperationSize:    2000,
			MaxOperationCount:   10000,
		})

		client, err := New([]svcprotocol.Version{v1_0})
		require.NotNil(t, client)
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		client, err := New(nil)
		require.Nil(t, client)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must provide at least one protocol version")
	})
}

func TestClient_Current(t *testing.T) {
	v1_0 := &svcmocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &svcmocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	t.Run("success - default", func(t *testing.T) {
		versions := []svcprotocol.Version{v1_0, v0_1}

		client, err := New(versions)
		require.NotNil(t, client)
		require.NoError(t, err)

		p, err := client.Current()
		require.NoError(t, err)
		require.Equal(t, uint(10000), p.Protocol().MaxOperationCount)
	})

	t.Run("success - with current protocol version", func(t *testing.T) {
		versions := []svcprotocol.Version{v0_1, v1_0}

		client, err := New(versions, WithCurrentProtocolVersion("0.1"))
		require.NotNil(t, client)
		require.NoError(t, err)

		p, err := client.Current()
		require.NoError(t, err)
		require.Equal(t, uint(100), p.Protocol().MaxOperationCount)
	})
}

func TestClient_Get(t *testing.T) {
	v1_0 := &svcmocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &svcmocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	versions := []svcprotocol.Version{v1_0, v0_1}

	client, err := New(versions)
	require.NotNil(t, client)
	require.NoError(t, err)

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
