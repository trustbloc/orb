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

func TestContextProperty(t *testing.T) {
	const (
		jsonContext      = `"https://www.w3.org/2018/credentials/v1"`
		jsonMultiContext = `["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/v1"]`
	)

	require.Nil(t, NewContextProperty())

	t.Run("Single context", func(t *testing.T) {
		p := NewContextProperty(ContextCredentials)
		require.NotNil(t, p)

		contexts := p.GetContexts()
		require.Len(t, contexts, 1)
		require.Equal(t, ContextCredentials, contexts[0])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		require.Equal(t, jsonContext, string(bytes))

		p2 := &ContextProperty{}
		require.NoError(t, json.Unmarshal([]byte(jsonContext), p2))
		require.True(t, p2.Contains(ContextCredentials))
		require.False(t, p2.ContainsAny(ContextSecurity))
	})

	t.Run("Multiple contexts", func(t *testing.T) {
		p := NewContextProperty(ContextCredentials, ContextSecurity)
		require.NotNil(t, p)

		contexts := p.GetContexts()
		require.Len(t, contexts, 2)
		require.Equal(t, ContextCredentials, contexts[0])
		require.Equal(t, ContextSecurity, contexts[1])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		require.Equal(t, jsonMultiContext, string(bytes))

		p2 := &ContextProperty{}
		require.NoError(t, json.Unmarshal([]byte(jsonMultiContext), p2))
		require.True(t, p2.Contains(ContextCredentials, ContextSecurity))
		require.False(t, p2.Contains(ContextCredentials, ContextOrb))
		require.True(t, p2.ContainsAny(ContextSecurity))
	})
}
