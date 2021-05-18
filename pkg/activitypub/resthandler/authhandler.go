/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

type authorizeActorFunc func(actorIRI *url.URL) (bool, error)

type authHandler struct {
	*Config

	endpoint       string
	authTokens     []string
	verifier       signatureVerifier
	activityStore  store.Store
	authorizeActor authorizeActorFunc
	writeResponse  func(w http.ResponseWriter, status int, body []byte)
}

func newAuthHandler(cfg *Config, endpoint, method string, s store.Store, verifier signatureVerifier,
	authorizeActor authorizeActorFunc) *authHandler {
	ep := fmt.Sprintf("%s%s", cfg.BasePath, endpoint)

	authTokens, err := resolveAuthTokens(ep, method, cfg.AuthTokensDef, cfg.AuthTokens)
	if err != nil {
		// This would occur on startup due to bad configuration, so it's better to panic.
		panic(fmt.Errorf("resolve authorization tokens: %w", err))
	}

	return &authHandler{
		Config:         cfg,
		endpoint:       ep,
		authTokens:     authTokens,
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
	if h.authorizeWithBearerToken(req) {
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

func (h *authHandler) authorizeWithBearerToken(req *http.Request) bool {
	// Open access.
	if len(h.authTokens) == 0 {
		logger.Debugf("[%s] No auth token required.", h.endpoint)

		return true
	}

	logger.Debugf("[%s] Auth tokens required: %s", h.endpoint, h.authTokens)

	actHdr := req.Header.Get(authHeader)
	if actHdr == "" {
		logger.Debugf("[%s] Bearer token not found in header", h.endpoint)

		return false
	}

	// Compare the header against all tokens. If any match then we allow the request.
	for _, token := range h.authTokens {
		logger.Debugf("[%s] Checking token %s", h.endpoint, token)

		if subtle.ConstantTimeCompare([]byte(actHdr), []byte(tokenPrefix+token)) == 1 {
			logger.Debugf("[%s] Found token %s", h.endpoint, token)

			return true
		}
	}

	return false
}

func resolveAuthTokens(endpoint, method string, authTokensDef []*AuthTokenDef,
	authTokenMap map[string]string) ([]string, error) {
	var authTokens []string

	for _, def := range authTokensDef {
		ok, err := endpointMatches(endpoint, def.EndpointExpression)
		if err != nil {
			return nil, err
		}

		if !ok {
			continue
		}

		var tokens []string

		if method == http.MethodPost {
			tokens = def.WriteTokens
		} else {
			tokens = def.ReadTokens
		}

		for _, tokenID := range tokens {
			token, ok := authTokenMap[tokenID]
			if !ok {
				return nil, fmt.Errorf("token not found: %s", tokenID)
			}

			authTokens = append(authTokens, token)
		}

		break
	}

	logger.Debugf("[%s] Authorization tokens: %s", endpoint, authTokens)

	return authTokens, nil
}

func endpointMatches(endpoint, pattern string) (bool, error) {
	ok, err := regexp.MatchString(pattern, endpoint)
	if err != nil {
		return false, fmt.Errorf("match endpoint pattern %s: %w", pattern, err)
	}

	logger.Debugf("[%s] Endpoint matches pattern [%s]: %t", endpoint, pattern, ok)

	return ok, nil
}
