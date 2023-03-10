/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
)

//go:generate counterfeiter -o ../mocks/authtokenmgr.gen.go --fake-name AuthTokenMgr . authTokenManager

func TestNewAuthHandler(t *testing.T) {
	const inboxURL = "https://example.com/services/orb/inboxbox"

	log.SetLevel("activitypub_resthandler", log.DEBUG)

	cfg := &Config{
		BasePath:               basePath,
		ObjectIRI:              serviceIRI,
		VerifyActorInSignature: true,
	}

	activityStore := memstore.New("")

	t.Run("POST with auth token -> success", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, &mocks.SignatureVerifier{}, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("GET with auth token -> success", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}

		h := NewAuthHandler(cfg, InboxPath, http.MethodGet, activityStore, &mocks.SignatureVerifier{}, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "READ_TOKEN"}

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("With invalid auth token -> error", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin"}, nil)

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, &mocks.SignatureVerifier{}, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)
		req.Header[authHeader] = []string{tokenPrefix + "INVALID_TOKEN"}

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})

	t.Run("With HTTP signature -> success", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin"}, nil)

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, cfg.ObjectIRI, nil)

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, verifier, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("No auth token definitions -> success", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}

		h := NewAuthHandler(
			&Config{
				BasePath:  basePath,
				ObjectIRI: serviceIRI,
			},
			InboxPath, http.MethodPost, activityStore, &mocks.SignatureVerifier{}, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodPost, inboxURL, nil)

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, cfg.ObjectIRI.String(), actorIRI.String())
	})

	t.Run("Invalid auth token definitions -> panic", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns(nil, errors.New("injected token manager error"))

		require.Panics(t, func() {
			h := NewAuthHandler(
				&Config{
					BasePath:  basePath,
					ObjectIRI: serviceIRI,
				},
				InboxPath, http.MethodGet, activityStore, &mocks.SignatureVerifier{}, tm,
				func(actorIRI *url.URL) (bool, error) {
					return true, nil
				},
			)
			require.NotNil(t, h)
		})
	})

	t.Run("No token and no HTTP signature verifier -> fail", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"read"}, nil)

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, nil, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)

		ok, actorIRI, err := h.Authorize(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})

	t.Run("HTTP signature verifier error -> fail", func(t *testing.T) {
		errExpected := errors.New("injected verifier error")

		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin"}, nil)

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, errExpected)

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, verifier, tm,
			func(actorIRI *url.URL) (bool, error) {
				return true, nil
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)

		ok, actorIRI, err := h.Authorize(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})

	t.Run("Authorize actor error -> fail", func(t *testing.T) {
		errExpected := errors.New("injected Authorize error")

		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin"}, nil)

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, cfg.ObjectIRI, nil)

		h := NewAuthHandler(cfg, InboxPath, http.MethodPost, activityStore, verifier, tm,
			func(actorIRI *url.URL) (bool, error) {
				return false, errExpected
			},
		)
		require.NotNil(t, h)

		req := httptest.NewRequest(http.MethodGet, inboxURL, nil)

		ok, actorIRI, err := h.Authorize(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, ok)
		require.Nil(t, actorIRI)
	})
}
