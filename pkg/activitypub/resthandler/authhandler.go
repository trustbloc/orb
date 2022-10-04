/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/orb/internal/pkg/log"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
)

type authorizeActorFunc func(actorIRI *url.URL) (bool, error)

// AuthHandler handles authorization of an HTTP request. Both bearer token and HTTP signature authorization
// are performed.
type AuthHandler struct {
	*Config

	tokenVerifier  *auth.TokenVerifier
	endpoint       string
	verifier       signatureVerifier
	activityStore  store.Store
	authorizeActor authorizeActorFunc
	writeResponse  func(w http.ResponseWriter, status int, body []byte)
	logger         *log.StructuredLog
}

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// NewAuthHandler returns a new authorization handler.
func NewAuthHandler(cfg *Config, endpoint, method string, s store.Store, verifier signatureVerifier,
	tm authTokenManager, authorizeActor authorizeActorFunc) *AuthHandler {
	ep := fmt.Sprintf("%s%s", cfg.BasePath, endpoint)

	logger := log.NewStructured(loggerModule, log.WithFields(log.WithServiceEndpoint(ep)))

	h := &AuthHandler{
		Config:         cfg,
		tokenVerifier:  auth.NewTokenVerifier(tm, ep, method),
		endpoint:       ep,
		verifier:       verifier,
		activityStore:  s,
		authorizeActor: authorizeActor,
		logger:         logger,
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			w.WriteHeader(status)

			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					logger.Warn("Unable to write response", log.WithError(err))

					return
				}

				log.WroteResponse(logger, body)
			}
		},
	}

	if h.authorizeActor == nil {
		h.authorizeActor = h.ensureActorIsWitnessOrFollower
	}

	return h
}

// Authorize authorizes the request, first checking the required bearer token and then, if the bearer token was not
// provided, the HTTP signature.
func (h *AuthHandler) Authorize(req *http.Request) (bool, *url.URL, error) {
	if h.tokenVerifier.Verify(req) {
		h.logger.Debug("Authorization succeeded using bearer token for request", log.WithRequestURL(req.URL))

		// The bearer of the token is assumed to be this service. If it isn't then validation
		// should fail in subsequent checks.
		return true, h.ObjectIRI, nil
	}

	h.logger.Debug("Authorization failed using bearer token for request", log.WithRequestURL(req.URL))

	if h.verifier == nil {
		return false, nil, nil
	}

	h.logger.Debug("Checking HTTP signature for request ...", log.WithRequestURL(req.URL))

	// Check HTTP signature.
	ok, actorIRI, err := h.verifier.VerifyRequest(req)
	if err != nil {
		return false, nil, fmt.Errorf("verify HTTP signature: %w", err)
	}

	if !ok {
		h.logger.Debug("Authorization failed using HTTP signature for request.", log.WithRequestURL(req.URL))

		return false, nil, nil
	}

	ok, err = h.authorizeActor(actorIRI)
	if err != nil {
		return false, nil, fmt.Errorf("authorize actor [%s]: %w", actorIRI, err)
	}

	h.logger.Debug("Authorization succeeded using HTTP signature for request.", log.WithRequestURL(req.URL))

	return ok, actorIRI, nil
}

func (h *AuthHandler) ensureActorIsWitnessOrFollower(actorIRI *url.URL) (bool, error) {
	if !h.VerifyActorInSignature {
		return true, nil
	}

	// Ensure that the actor is a follower or a witness, otherwise deny access.
	isFollower, err := h.hasReference(store.Follower, actorIRI)
	if err != nil {
		return false, fmt.Errorf("check follower: %w", err)
	}

	if !isFollower {
		isWitness, err := h.hasReference(store.Witness, actorIRI)
		if err != nil {
			return false, fmt.Errorf("check witness: %w", err)
		}

		if !isWitness {
			h.logger.Info("Denying access since actor is neither a follower or a witness.", log.WithActorIRI(actorIRI))

			return false, nil
		}
	}

	return true, nil
}

func (h *AuthHandler) hasReference(refType store.ReferenceType, refIRI *url.URL) (bool, error) {
	it, err := h.activityStore.QueryReferences(refType,
		store.NewCriteria(
			store.WithObjectIRI(h.ObjectIRI),
			store.WithReferenceIRI(refIRI),
		),
	)
	if err != nil {
		return false, fmt.Errorf("query references: %w", err)
	}

	defer func() {
		err = it.Close()
		if err != nil {
			log.CloseIteratorError(h.logger, err)
		}
	}()

	_, err = it.Next()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("get next reference: %w", err)
	}

	return true, nil
}
