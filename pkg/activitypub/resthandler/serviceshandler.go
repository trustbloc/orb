/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"net/http"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

// Services implements the 'services' REST handler to retrieve a given ActivityPub service (actor).
type Services struct {
	*handler
}

// NewServices returns a new 'services' REST handler.
func NewServices(cfg *Config, activityStore spi.Store) *Services {
	h := &Services{}

	h.handler = newHandler("", cfg, activityStore, h.handle)

	return h
}

func (h *Services) handle(w http.ResponseWriter, _ *http.Request) {
	service, err := h.activityStore.GetActor(h.ObjectIRI)
	if err != nil {
		logger.Errorf("[%s] Error retrieving service [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	serviceBytes, err := h.marshal(service)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal service [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(w, http.StatusOK, serviceBytes)
}
