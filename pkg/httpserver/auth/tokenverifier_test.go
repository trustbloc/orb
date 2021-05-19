/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenVerifier(t *testing.T) {
	cfg := Config{
		AuthTokensDef: []*TokenDef{
			{
				EndpointExpression: "/services/orb/outbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
			{
				EndpointExpression: "/services/orb/inbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
		},
		AuthTokens: map[string]string{
			"read":  "READ_TOKEN",
			"admin": "ADMIN_TOKEN",
		},
	}

	t.Run("Success", func(t *testing.T) {
		v1 := NewTokenVerifier(cfg, "/services/orb/outbox", http.MethodPost)
		require.NotNil(t, v1)

		v2 := NewTokenVerifier(cfg, "/services/orb/outbox", http.MethodGet)
		require.NotNil(t, v2)
	})

	t.Run("Token not found -> panic", func(t *testing.T) {
		c := Config{
			AuthTokensDef: []*TokenDef{
				{
					EndpointExpression: "/services/orb/outbox",
					ReadTokens:         []string{"admin", "read"},
				},
			},
		}

		require.Panics(t, func() {
			NewTokenVerifier(c, "/services/orb/outbox", http.MethodGet)
		})
	})

	t.Run("POST with auth token -> success", func(t *testing.T) {
		v := NewTokenVerifier(cfg, "/services/orb/outbox", http.MethodPost)
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", nil)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		require.True(t, v.Verify(req))
	})

	t.Run("GET with no auth token -> unauthorized", func(t *testing.T) {
		v := NewTokenVerifier(cfg, "/services/orb/outbox", http.MethodGet)
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)

		require.False(t, v.Verify(req))
	})

	t.Run("GET with invalid auth token -> unauthorized", func(t *testing.T) {
		v := NewTokenVerifier(cfg, "/services/orb/outbox", http.MethodGet)
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)
		req.Header[authHeader] = []string{tokenPrefix + "INVALID_TOKEN"}

		require.False(t, v.Verify(req))
	})

	t.Run("Open access -> success", func(t *testing.T) {
		v := NewTokenVerifier(Config{}, "/services/orb/outbox", http.MethodGet)
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)

		require.True(t, v.Verify(req))
	})
}
