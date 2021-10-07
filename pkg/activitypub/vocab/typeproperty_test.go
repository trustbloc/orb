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
		jsonMultiType = `["Create","AnchorEvent"]`
	)

	t.Run("Nil type", func(t *testing.T) {
		p := NewTypeProperty()
		require.Nil(t, p)
		require.False(t, p.Is(TypeCreate))
		require.False(t, p.IsAny(TypeCreate))
		require.Empty(t, p.Types())
		require.Equal(t, "", p.String())
	})

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
		require.Equal(t, "Create", p2.String())
	})

	t.Run("Multiple types", func(t *testing.T) {
		p := NewTypeProperty(TypeCreate, TypeAnchorEvent)
		require.NotNil(t, p)

		types := p.Types()
		require.Len(t, types, 2)
		require.Equal(t, TypeCreate, types[0])
		require.Equal(t, TypeAnchorEvent, types[1])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		require.Equal(t, jsonMultiType, string(bytes))

		p2 := &TypeProperty{}
		require.NoError(t, json.Unmarshal([]byte(jsonMultiType), p2))
		require.True(t, p2.Is(TypeCreate))
		require.False(t, p2.Is(TypeCreate, TypeFollow))
		require.Equal(t, "[Create AnchorEvent]", p2.String())
	})
}
