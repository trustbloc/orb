/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

var logger = log.New("activitypub_resthandler")

type handler struct {
	endpoint      string
	activityStore spi.Store
	serviceIRI    *url.URL
	handler       common.HTTPRequestHandler
	marshal       func(v interface{}) ([]byte, error)
	writeResponse func(w http.ResponseWriter, status int, body []byte)
}

func newHandler(endpoint string, serviceIRI *url.URL, s spi.Store, h common.HTTPRequestHandler) *handler {
	return &handler{
		endpoint:      endpoint,
		activityStore: s,
		serviceIRI:    serviceIRI,
		handler:       h,
		marshal:       json.Marshal,
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					logger.Warnf("[%s] Unable to write response: %s", endpoint, err)

					return
				}

				logger.Debugf("[%s] Wrote response: %s", endpoint, body)
			}

			w.WriteHeader(status)
		},
	}
}

// Path returns the base path of the target URL for this handler.
func (h *handler) Path() string {
	return h.endpoint
}

// Method returns the HTTP method, which is always GET.
func (h *handler) Method() string {
	return http.MethodGet
}

// Handler returns the handler that should be invoked when an HTTP GET is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *handler) Handler() common.HTTPRequestHandler {
	return h.handler
}
