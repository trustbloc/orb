/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"net/http"
	"net/url"

	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
)

type authorizeActorFunc func(actorIRI *url.URL) (bool, error)

type authHandler struct {
	*Config
	tokenVerifier *auth.TokenVerifier

	endpoint       string
	verifier       signatureVerifier
	activityStore  store.Store
	authorizeActor authorizeActorFunc
	writeResponse  func(w http.ResponseWriter, status int, body []byte)
}

func newAuthHandler(cfg *Config, endpoint, method string, s store.Store, verifier signatureVerifier,
	authorizeActor authorizeActorFunc) *authHandler {
	ep := fmt.Sprintf("%s%s", cfg.BasePath, endpoint)

	return &authHandler{
		Config:         cfg,
		tokenVerifier:  auth.NewTokenVerifier(cfg.Config, ep, method),
		endpoint:       ep,
		verifier:       verifier,
		activityStore:  s,
		authorizeActor: authorizeActor,
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			w.WriteHeader(status)

			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					logger.Warnf("[%s] Unable to write response: %s", ep, err)

					return
				}

				logger.Debugf("[%s] Wrote response: %s", ep, body)
			}
		},
	}
}

func (h *authHandler) authorize(req *http.Request) (bool, *url.URL, error) {
	if h.tokenVerifier.Verify(req) {
		logger.Debugf("[%s] Authorization succeeded using bearer token", h.endpoint)

		// The bearer of the token is assumed to be this service. If it isn't then validation
		// should fail in subsequent checks.
		return true, h.ObjectIRI, nil
	}

	logger.Debugf("[%s] Authorization failed using bearer token.", h.endpoint)

	if h.verifier == nil {
		return false, nil, nil
	}

	logger.Debugf("[%s] Checking HTTP signature...", h.endpoint)

	// Check HTTP signature.
	ok, actorIRI, err := h.verifier.VerifyRequest(req)
	if err != nil {
		return false, nil, fmt.Errorf("verify HTTP signature: %w", err)
	}

	if !ok {
		logger.Debugf("[%s] Authorization failed using HTTP signature.", h.endpoint)

		return false, nil, nil
	}

	ok, err = h.authorizeActor(actorIRI)
	if err != nil {
		return false, nil, fmt.Errorf("authorize actor [%s]: %w", actorIRI, err)
	}

	return ok, actorIRI, nil
}
