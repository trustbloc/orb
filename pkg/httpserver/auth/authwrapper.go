/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

const unauthorizedResponse = "Unauthorized.\n"

// HandlerWrapper wraps an existing HTTP handler and performs bearer token authorization.
// If authorized then the wrapped handler is invoked.
type HandlerWrapper struct {
	common.HTTPHandler

	verifier      *TokenVerifier
	handler       common.HTTPHandler
	handleRequest common.HTTPRequestHandler
	writeResponse func(w http.ResponseWriter, status int, body []byte)
	logger        *log.Log
}

// NewHandlerWrapper returns a handler that first performs bearer token authorization and, if authorized,
// invokes the wrapped handler.
func NewHandlerWrapper(handler common.HTTPHandler, tm tokenManager) *HandlerWrapper {
	logger := log.New(loggerModule, log.WithFields(logfields.WithServiceEndpoint(handler.Path())))

	return &HandlerWrapper{
		verifier:      NewTokenVerifier(tm, handler.Path(), handler.Method()),
		HTTPHandler:   handler,
		handler:       handler,
		handleRequest: handler.Handler(),
		logger:        logger,
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			w.WriteHeader(status)

			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					log.WriteResponseBodyError(logger, err)

					return
				}

				log.WroteResponse(logger, body)
			}
		},
	}
}

// Handler returns the 'wrapper' handler.
func (h *HandlerWrapper) Handler() common.HTTPRequestHandler {
	return func(w http.ResponseWriter, req *http.Request) {
		if !h.verifier.Verify(req) {
			h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

			return
		}

		h.handleRequest(w, req)
	}
}
