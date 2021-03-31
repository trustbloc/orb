/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/context/protocol/client"
)

const ns = "did:orb"

func TestNew(t *testing.T) {
	p := New()
	require.NotNil(t, p)
}

func TestClientProvider_ForNamespace(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:       0,
		MaxOperationCount: 10,
	})

	versions := []protocol.Version{v1_0}

	pc := client.New(versions)
	require.NotNil(t, pc)

	p := New()
	require.NotNil(t, p)

	p.Add(ns, pc)

	t.Run("success", func(t *testing.T) {
		retClient, err := p.ForNamespace(ns)
		require.NoError(t, err)
		require.NotNil(t, retClient)

		cur, err := retClient.Current()
		require.NoError(t, err)
		require.Equal(t, uint(10), cur.Protocol().MaxOperationCount)
	})

	t.Run("error - client not found for namespace", func(t *testing.T) {
		retClient, err := p.ForNamespace("invalid")
		require.Error(t, err)
		require.Nil(t, retClient)
		require.Contains(t, err.Error(), "protocol client not defined for namespace: invalid")
	})
}
