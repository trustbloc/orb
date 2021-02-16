/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTypeProperty(t *testing.T) {
	const (
		jsonType      = `"Create"`
		jsonMultiType = `["Create","AnchorCredential"]`
	)

	require.Nil(t, NewTypeProperty())

	t.Run("Single type", func(t *testing.T) {
		p := NewTypeProperty(TypeCreate)
		require.NotNil(t, p)

		types := p.Types()
		require.Len(t, types, 1)
		require.Equal(t, TypeCreate, types[0])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		require.Equal(t, jsonType, string(bytes))

		p2 := &TypeProperty{}
		require.NoError(t, json.Unmarshal([]byte(jsonType), p2))
		require.True(t, p2.Is(TypeCreate))
		require.False(t, p2.IsAny(TypeAnchorCredential))
	})

	t.Run("Multiple types", func(t *testing.T) {
		p := NewTypeProperty(TypeCreate, TypeAnchorCredential)
		require.NotNil(t, p)

		types := p.Types()
		require.Len(t, types, 2)
		require.Equal(t, TypeCreate, types[0])
		require.Equal(t, TypeAnchorCredential, types[1])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		require.Equal(t, jsonMultiType, string(bytes))

		p2 := &TypeProperty{}
		require.NoError(t, json.Unmarshal([]byte(jsonMultiType), p2))
		require.True(t, p2.Is(TypeCreate, TypeAnchorCredential))
		require.False(t, p2.Is(TypeCreate, TypeFollow))
		require.True(t, p2.IsAny(TypeAnchorCredential))
	})
}
