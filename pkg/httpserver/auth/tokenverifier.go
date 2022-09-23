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

	"github.com/trustbloc/orb/internal/pkg/log"
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

type tokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// TokenVerifier authorizes requests with bearer tokens.
type TokenVerifier struct {
	endpoint   string
	authTokens []string
}

// NewTokenVerifier returns a verifier that performs bearer token authorization.
func NewTokenVerifier(tm tokenManager, endpoint, method string) *TokenVerifier {
	authTokens, err := tm.RequiredAuthTokens(endpoint, method)
	if err != nil {
		// This would occur on startup due to bad configuration, so it's better to panic.
		panic(fmt.Errorf("resolve authorization tokens: %w", err))
	}

	return &TokenVerifier{
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

type tokenDef struct {
	expr        *regexp.Regexp
	readTokens  []string
	writeTokens []string
}

// TokenManager manages the authorization tokens for both the client and server.
type TokenManager struct {
	tokenDefs  []*tokenDef
	authTokens map[string]string
}

// NewTokenManager returns a token mapper that performs bearer token authorization.
func NewTokenManager(cfg Config) (*TokenManager, error) {
	defs := make([]*tokenDef, len(cfg.AuthTokensDef))

	for i, def := range cfg.AuthTokensDef {
		expr, err := regexp.Compile(def.EndpointExpression)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint expression [%s]: %w", def.EndpointExpression, err)
		}

		defs[i] = &tokenDef{
			expr:        expr,
			readTokens:  def.ReadTokens,
			writeTokens: def.WriteTokens,
		}
	}

	return &TokenManager{
		tokenDefs:  defs,
		authTokens: cfg.AuthTokens,
	}, nil
}

// IsAuthRequired return true if authorization is required for the given endpoint/method.
func (m *TokenManager) IsAuthRequired(endpoint, method string) (bool, error) {
	for _, def := range m.tokenDefs {
		ok := def.expr.MatchString(endpoint)
		if !ok {
			continue
		}

		switch method {
		case http.MethodGet:
			if len(def.readTokens) > 0 {
				logger.Debugf("[%s] Authorization token(s) required for %s: %s", endpoint, method, def.readTokens)

				return true, nil
			}
		case http.MethodPost:
			if len(def.writeTokens) > 0 {
				logger.Debugf("[%s] Authorization token(s) required for %s: %s", endpoint, method, def.writeTokens)

				return true, nil
			}
		default:
			return false, fmt.Errorf("unsupported HTTP method [%s]", method)
		}
	}

	logger.Debugf("[%s] Authorization not required for %s", endpoint, method)

	return false, nil
}

// RequiredAuthTokens returns the authorization tokens required for the given endpoint and method.
func (m *TokenManager) RequiredAuthTokens(endpoint, method string) ([]string, error) {
	var authTokens []string

	for _, def := range m.tokenDefs {
		ok := def.expr.MatchString(endpoint)
		if !ok {
			continue
		}

		var tokens []string

		switch method {
		case http.MethodGet:
			tokens = def.readTokens
		case http.MethodPost:
			tokens = def.writeTokens
		default:
			return nil, fmt.Errorf("unsupported HTTP method [%s]", method)
		}

		for _, tokenID := range tokens {
			token, ok := m.authTokens[tokenID]
			if !ok {
				return nil, fmt.Errorf("token not found: %s", tokenID)
			}

			authTokens = append(authTokens, token)
		}

		break
	}

	logger.Debugf("[%s] Authorization tokens required for %s: %s", endpoint, method, authTokens)

	return authTokens, nil
}
