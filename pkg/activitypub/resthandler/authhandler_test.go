/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
)

func TestNewAuthHandler(t *testing.T) {
	const inboxURL = "https://example.com/services/orb/inboxbox"

	log.SetLevel("activitypub_resthandler", log.DEBUG)

	cfg := &Config{
		BasePath:               basePath,
		ObjectIRI:              serviceIRI,
		VerifyActorInSignature: true,
		AuthTokensDef: []*AuthTokenDef{
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

	t.Run("POST with auth token -> success", func(t *testing.T) {
		h := newAuthHandler(cfg, InboxPath, http.MethodPost, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("GET with auth token -> success", func(t *testing.T) {
		h := newAuthHandler(cfg, InboxPath, http.MethodGet, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "READ_TOKEN"}

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("With invalid auth token -> error", func(t *testing.T) {
		h := newAuthHandler(cfg, InboxPath, http.MethodPost, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "INVALID_TOKEN"}

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})

	t.Run("With HTTP signature -> success", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, cfg.ObjectIRI, nil)

		h := newAuthHandler(cfg, InboxPath, http.MethodPost, verifier)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("No auth token definitions -> success", func(t *testing.T) {
		h := newAuthHandler(
			&Config{
				BasePath:  basePath,
				ObjectIRI: serviceIRI,
			},
			InboxPath, http.MethodPost, &mocks.SignatureVerifier{},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("Invalid auth token definitions -> panic", func(t *testing.T) {
		require.Panics(t, func() {
			h := newAuthHandler(
				&Config{
					BasePath:  basePath,
					ObjectIRI: serviceIRI,
					AuthTokensDef: []*AuthTokenDef{
						{
							EndpointExpression: "/services/orb/inbox",
							ReadTokens:         []string{"admin", "read"},
						},
					},
				},
				InboxPath, http.MethodGet, &mocks.SignatureVerifier{},
			)
			require.NotNil(t, h)
		})
	})

	t.Run("No token and no HTTP signature verifier -> fail", func(t *testing.T) {
		h := newAuthHandler(cfg, InboxPath, http.MethodPost, nil)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)

		ok, actorIRI, err := h.authorize(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})

	t.Run("HTTP signature verifier error -> fail", func(t *testing.T) {
		errExpected := errors.New("injected verifier error")

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, errExpected)

		h := newAuthHandler(cfg, InboxPath, http.MethodPost, verifier)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)

		ok, actorIRI, err := h.authorize(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})
}
