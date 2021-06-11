/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/didanchor"
)

const (
	suffixPathVariable = "suffix"
	endpoint           = "/anchor/{" + suffixPathVariable + "}"

	notFoundResponse            = "Not Found."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("did-anchor-handler")

// DidAnchorHandler retrieves the latest anchor (cid) for this did (suffix).
type DidAnchorHandler struct {
	*resthandler.AuthHandler

	didAnchorStore didAnchors
}

type didAnchors interface {
	Get(suffix string) (string, error)
}

// Path returns the HTTP REST endpoint for the service.
func (h *DidAnchorHandler) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the service.
func (h *DidAnchorHandler) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the service.
func (h *DidAnchorHandler) Handler() common.HTTPRequestHandler {
	return h.handle
}

// New returns a new DidAnchorHandler.
func New(didAnchorStore didAnchors) *DidAnchorHandler {
	h := &DidAnchorHandler{
		didAnchorStore: didAnchorStore,
	}

	return h
}

func (h *DidAnchorHandler) handle(w http.ResponseWriter, req *http.Request) {
	suffix := mux.Vars(req)[suffixPathVariable]

	anchor, err := h.didAnchorStore.Get(suffix)
	if err != nil {
		if errors.Is(err, didanchor.ErrDataNotFound) {
			writeResponse(w, http.StatusNotFound, []byte(notFoundResponse))

			return
		}

		logger.Errorf("[%s] Error retrieving anchor for suffix[%s]: %s", endpoint, suffix, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] latest anchor for suffix[%s]: %s", endpoint, suffix, anchor)

	writeResponse(w, http.StatusOK, []byte(anchor))
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warnf("[%s] Unable to write response: %s", endpoint, err)

			return
		}

		logger.Debugf("[%s] Wrote response: %s", endpoint, body)
	}
}
