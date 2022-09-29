/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcresthandler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
)

const idPathVariable = "id"

const (
	statusNotFoundResponse      = "Content Not Found."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.NewStructured("vc-rest-handler")

// Handler retrieves vc from verifiable credential store.
type Handler struct {
	store storage.Store
}

// Path returns the HTTP REST endpoint for retrieving verifiable credential.
func (h *Handler) Path() string {
	return fmt.Sprintf("/vc/{%s}", idPathVariable)
}

// Method returns the HTTP REST method for the verifiable credential.
func (h *Handler) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the Handler service.
func (h *Handler) Handler() common.HTTPRequestHandler {
	return h.handle
}

// New returns a new Handler.
func New(vcStore storage.Store) *Handler {
	h := &Handler{
		store: vcStore,
	}

	return h
}

func (h *Handler) handle(w http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)[idPathVariable]

	vc, err := h.store.Get(id)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			logger.Debug("Verifiable credential not found", log.WithVerifiableCredentialID(id), log.WithError(err))

			writeResponse(w, http.StatusNotFound, []byte(statusNotFoundResponse))

			return
		}

		logger.Error("Error retrieving verifiable credential", log.WithVerifiableCredentialID(id), log.WithError(err))

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	writeResponse(w, http.StatusOK, vc)
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			log.WriteResponseBodyError(logger.Warn, err)

			return
		}

		log.WroteResponse(logger.Debug, body)
	}
}
