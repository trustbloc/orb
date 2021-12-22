/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
)

func TestTokenVerifier(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		v1 := NewTokenVerifier(&apmocks.AuthTokenMgr{}, http.MethodPost, "/services/orb/outbox")
		require.NotNil(t, v1)

		v2 := NewTokenVerifier(&apmocks.AuthTokenMgr{}, http.MethodGet, "/services/orb/outbox")
		require.NotNil(t, v2)
	})

	t.Run("Token not found -> panic", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns(nil, errors.New("injected token manager error"))

		require.Panics(t, func() {
			NewTokenVerifier(tm, http.MethodGet, "/services/orb/outbox")
		})
	})

	t.Run("POST with auth token -> success", func(t *testing.T) {
		v := NewTokenVerifier(&apmocks.AuthTokenMgr{}, http.MethodPost, "/services/orb/outbox")
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", nil)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		require.True(t, v.Verify(req))
	})

	t.Run("GET with no auth token -> unauthorized", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin", "read"}, nil)

		v := NewTokenVerifier(tm, http.MethodGet, "/services/orb/outbox")
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)

		require.False(t, v.Verify(req))
	})

	t.Run("GET with invalid auth token -> unauthorized", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin", "read"}, nil)

		v := NewTokenVerifier(tm, http.MethodGet, "/services/orb/outbox")
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)
		req.Header[authHeader] = []string{tokenPrefix + "INVALID_TOKEN"}

		require.False(t, v.Verify(req))
	})

	t.Run("Open access -> success", func(t *testing.T) {
		v := NewTokenVerifier(&apmocks.AuthTokenMgr{}, http.MethodGet, "/services/orb/outbox")
		require.NotNil(t, v)

		req := httptest.NewRequest(http.MethodGet, "/services/orb/outbox", nil)

		require.True(t, v.Verify(req))
	})
}

func TestTokenManager(t *testing.T) {
	cfg := Config{
		AuthTokensDef: []*TokenDef{
			{
				EndpointExpression: "/services/orb/outbox",
				WriteTokens:        []string{"admin"},
			},
			{
				EndpointExpression: "/services/orb/inbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
			{
				EndpointExpression: "/services/orb/acceptlist",
				ReadTokens:         []string{"invalid"},
			},
		},
		AuthTokens: map[string]string{
			"read":  "READ_TOKEN",
			"admin": "ADMIN_TOKEN",
		},
	}

	t.Run("IsAuthRequired -> success", func(t *testing.T) {
		tm, err := NewTokenManager(cfg)
		require.NoError(t, err)
		require.NotNil(t, tm)

		authRequired, err := tm.IsAuthRequired("/services/orb/outbox", http.MethodPost)
		require.NoError(t, err)
		require.True(t, authRequired)

		authRequired, err = tm.IsAuthRequired("/services/orb/outbox", http.MethodGet)
		require.NoError(t, err)
		require.False(t, authRequired)

		authRequired, err = tm.IsAuthRequired("/services/orb/inbox", http.MethodGet)
		require.NoError(t, err)
		require.True(t, authRequired)

		authRequired, err = tm.IsAuthRequired("/services/orb/acceptlist", http.MethodPost)
		require.NoError(t, err)
		require.False(t, authRequired)
	})

	t.Run("IsAuthRequired -> error", func(t *testing.T) {
		tm, err := NewTokenManager(cfg)
		require.NoError(t, err)
		require.NotNil(t, tm)

		_, err = tm.IsAuthRequired("/services/orb/outbox", http.MethodConnect)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported HTTP method")
	})

	t.Run("RequiredAuthTokens -> success", func(t *testing.T) {
		tm, err := NewTokenManager(cfg)
		require.NoError(t, err)
		require.NotNil(t, tm)

		requiredTokens, err := tm.RequiredAuthTokens("/services/orb/outbox", http.MethodPost)
		require.NoError(t, err)
		require.Equal(t, []string{"ADMIN_TOKEN"}, requiredTokens)

		requiredTokens, err = tm.RequiredAuthTokens("/services/orb/outbox", http.MethodGet)
		require.NoError(t, err)
		require.Empty(t, requiredTokens)

		requiredTokens, err = tm.RequiredAuthTokens("/services/orb/inbox", http.MethodGet)
		require.NoError(t, err)
		require.Equal(t, []string{"ADMIN_TOKEN", "READ_TOKEN"}, requiredTokens)

		requiredTokens, err = tm.RequiredAuthTokens("/services/orb/acceptlist", http.MethodPost)
		require.NoError(t, err)
		require.Empty(t, requiredTokens)
	})

	t.Run("RequiredAuthTokens -> error", func(t *testing.T) {
		tm, err := NewTokenManager(cfg)
		require.NoError(t, err)
		require.NotNil(t, tm)

		_, err = tm.RequiredAuthTokens("/services/orb/outbox", http.MethodConnect)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported HTTP method")

		_, err = tm.RequiredAuthTokens("/services/orb/acceptlist", http.MethodGet)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token not found")
	})
}
