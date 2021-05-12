/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

type outbox interface {
	Post(activity *vocab.ActivityType) (*url.URL, error)
}

// Outbox implements a REST handler for posts to a service's outbox.
type Outbox struct {
	*Config
	*authHandler

	endpoint string
	ob       outbox
}

// NewPostOutbox returns a new REST handler to post activities to the outbox.
func NewPostOutbox(cfg *Config, ob outbox, verifier signatureVerifier) *Outbox {
	return &Outbox{
		Config:      cfg,
		authHandler: newAuthHandler(cfg, "/outbox", http.MethodPost, verifier),
		endpoint:    fmt.Sprintf("%s%s", cfg.BasePath, "/outbox"),
		ob:          ob,
	}
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
	ok, actorIRI, err := h.authorize(req)
	if err != nil {
		logger.Errorf("[%s] Error authorizing request: %s", h.endpoint, err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if !ok {
		logger.Infof("[%s] Unauthorized", h.endpoint)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	activityBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[%s] Error reading request body: %s", h.endpoint, err)

		w.WriteHeader(http.StatusBadRequest)

		return
	}

	logger.Debugf("[%s] Posting activity %s", h.endpoint, activityBytes)

	activity, err := h.unmarshalAndValidateActivity(actorIRI, activityBytes)
	if err != nil {
		logger.Errorf("[%s] Invalid activity: %s", h.endpoint, err)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	_, err = h.ob.Post(activity)
	if err != nil {
		logger.Errorf("[%s] Error posting activity: %s", h.endpoint, err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}
}

func (h *Outbox) unmarshalAndValidateActivity(actorIRI *url.URL, activityBytes []byte) (*vocab.ActivityType, error) {
	if h.VerifyActorInSignature {
		if h.ObjectIRI.String() != actorIRI.String() {
			return nil, fmt.Errorf("only actor [%s] may post to this outbox", h.ObjectIRI)
		}
	}

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
