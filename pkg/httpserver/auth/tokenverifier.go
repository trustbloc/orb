/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("httpserver")

const (
	authHeader  = "Authorization"
	tokenPrefix = "Bearer "
)

// TokenDef contains authorization bearer token definitions.
type TokenDef struct {
	EndpointExpression string
	ReadTokens         []string
	WriteTokens        []string
}

// Config contains the authorization token configuration.
type Config struct {
	AuthTokensDef []*TokenDef
	AuthTokens    map[string]string
}

// TokenVerifier authorizes requests with bearer tokens.
type TokenVerifier struct {
	Config

	endpoint   string
	authTokens []string
}

// NewTokenVerifier returns a verifier that performs bearer token authorization.
func NewTokenVerifier(cfg Config, endpoint, method string) *TokenVerifier {
	authTokens, err := resolveAuthTokens(endpoint, method, cfg.AuthTokensDef, cfg.AuthTokens)
	if err != nil {
		// This would occur on startup due to bad configuration, so it's better to panic.
		panic(fmt.Errorf("resolve authorization tokens: %w", err))
	}

	return &TokenVerifier{
		Config:     cfg,
		endpoint:   endpoint,
		authTokens: authTokens,
	}
}

// Verify verifies that the request has the required bearer token. If not, false is returned.
func (h *TokenVerifier) Verify(req *http.Request) bool {
	if len(h.authTokens) == 0 {
		// Open access.
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

func resolveAuthTokens(endpoint, method string, authTokensDef []*TokenDef,
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
