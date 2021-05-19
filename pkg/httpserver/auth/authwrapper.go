/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
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
}

// NewHandlerWrapper returns a handler that first performs bearer token authorization and, if authorized,
// invokes the wrapped handler.
func NewHandlerWrapper(cfg Config, handler common.HTTPHandler) *HandlerWrapper {
	return &HandlerWrapper{
		verifier:      NewTokenVerifier(cfg, handler.Path(), handler.Method()),
		HTTPHandler:   handler,
		handler:       handler,
		handleRequest: handler.Handler(),
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			w.WriteHeader(status)

			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					logger.Warnf("[%s] Unable to write response: %s", handler.Path(), err)

					return
				}

				logger.Debugf("[%s] Wrote response: %s", handler.Path(), body)
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
