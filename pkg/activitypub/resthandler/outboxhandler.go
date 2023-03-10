/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

type outbox interface {
	Post(activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

// Outbox implements a REST handler for posts to a service's outbox.
type Outbox struct {
	*Config
	*AuthHandler

	endpoint string
	ob       outbox
	marshal  func(v interface{}) ([]byte, error)
}

// NewPostOutbox returns a new REST handler to post activities to the outbox.
func NewPostOutbox(cfg *Config, ob outbox, s store.Store, verifier signatureVerifier, tm authTokenManager) *Outbox {
	h := &Outbox{
		Config:   cfg,
		endpoint: fmt.Sprintf("%s%s", cfg.BasePath, "/outbox"),
		ob:       ob,
		marshal:  json.Marshal,
	}

	h.AuthHandler = NewAuthHandler(cfg, "/outbox", http.MethodPost, s, verifier, tm, h.authorizeActor)

	return h
}

// Method returns the HTTP method, which is always POST.
func (h *Outbox) Method() string {
	return http.MethodPost
}

// Path returns the base path of the target URL for this handler.
func (h *Outbox) Path() string {
	return h.endpoint
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *Outbox) Handler() common.HTTPRequestHandler {
	return h.handlePost
}

func (h *Outbox) handlePost(w http.ResponseWriter, req *http.Request) {
	ok, _, err := h.Authorize(req)
	if err != nil {
		h.logger.Error("Error authorizing request", log.WithError(err), logfields.WithRequestURL(req.URL))

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	if !ok {
		h.logger.Info("Unauthorized", logfields.WithRequestURL(req.URL))

		h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

		return
	}

	activityBytes, err := io.ReadAll(req.Body)
	if err != nil {
		h.logger.Error("Error reading request body", log.WithError(err), logfields.WithRequestURL(req.URL))

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.logger.Debug("Posting activity", logfields.WithData(activityBytes))

	activity, err := h.unmarshalAndValidateActivity(activityBytes)
	if err != nil {
		h.logger.Debug("Invalid activity", log.WithError(err))

		h.writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	activityID, err := h.ob.Post(activity)
	if err != nil {
		if orberrors.IsBadRequest(err) {
			h.logger.Debug("Error posting activity", log.WithError(err))

			h.writeResponse(w, http.StatusBadRequest, []byte(err.Error()))
		} else {
			h.logger.Error("Error posting activity", log.WithError(err))

			h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))
		}

		return
	}

	activityIDBytes, err := h.marshal(activityID.String())
	if err != nil {
		h.logger.Error("Error marshaling activity ID", log.WithError(err))

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.writeResponse(w, http.StatusOK, activityIDBytes)
}

func (h *Outbox) unmarshalAndValidateActivity(activityBytes []byte) (*vocab.ActivityType, error) {
	activity := &vocab.ActivityType{}

	err := json.Unmarshal(activityBytes, activity)
	if err != nil {
		return nil, fmt.Errorf("unmarshal activity: %w", err)
	}

	if activity.Actor() == nil {
		return nil, fmt.Errorf("no actor specified in activity [%s]", activity.ID())
	}

	if activity.Actor().String() != h.ObjectIRI.String() {
		return nil, fmt.Errorf("actor in activity [%s] does not match the actor in the HTTP signature [%s]",
			activity.ID(), h.ObjectIRI)
	}

	return activity, nil
}

func (h *Outbox) authorizeActor(actorIRI *url.URL) (bool, error) {
	if !h.VerifyActorInSignature {
		return true, nil
	}

	// Ensure that the actor is the local service.
	if actorIRI.String() != h.ObjectIRI.String() {
		h.logger.Info("Denying access to actor to post to the outbox", logfields.WithActorIRI(actorIRI))

		return false, nil
	}

	return true, nil
}
