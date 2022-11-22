/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package maintenance

import (
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
)

const loggerModule = "maintenance"

const serviceUnavailableResponse = "Service Unavailable.\n"

// HandlerWrapper wraps an existing HTTP handler and call to handler endpoint returns 503 (Service Unavailable).
// If authorized then the wrapped handler is invoked.
type HandlerWrapper struct {
	common.HTTPHandler

	writeResponse func(w http.ResponseWriter, status int, body []byte)
	logger        *log.Log
}

// NewMaintenanceWrapper will return service unavailable for handler that was passed in.
func NewMaintenanceWrapper(handler common.HTTPHandler) *HandlerWrapper {
	logger := log.New(loggerModule, log.WithFields(log.WithServiceEndpoint(handler.Path())))

	return &HandlerWrapper{
		HTTPHandler: handler,
		logger:      logger,
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
		h.writeResponse(w, http.StatusServiceUnavailable, []byte(serviceUnavailableResponse))
	}
}
