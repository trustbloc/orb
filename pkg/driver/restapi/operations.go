/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"
)

const (
	resolveDIDEndpoint = "/1.0/identifiers/{id}"
	didLDJson          = "application/did+ld+json"
)

var logger = log.New("driver")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers.
type Operation struct {
	orbVDR vdr.VDR
}

// Config defines configuration for driver operations.
type Config struct {
	OrbVDR vdr.VDR
}

// New returns driver operation instance.
func New(config *Config) *Operation {
	return &Operation{orbVDR: config.OrbVDR}
}

func (o *Operation) resolveDIDHandler(rw http.ResponseWriter, req *http.Request) {
	didID := mux.Vars(req)["id"]

	if didID == "" {
		o.writeErrorResponse(rw, http.StatusBadRequest, "url param 'did' is missing")

		return
	}

	DocResolution, err := o.orbVDR.Read(didID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to resolve did: %s", err.Error()))

		return
	}

	bytes, err := DocResolution.JSONBytes()
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal doc resolution: %s", err.Error()))

		return
	}

	rw.Header().Set("Content-type", didLDJson)
	rw.WriteHeader(http.StatusOK)

	if _, err := rw.Write(bytes); err != nil {
		log.WriteResponseBodyError(logger, err)
	}
}

// writeErrorResponse writes interface value to response.
func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.WriteResponseBodyError(logger, err)
	}
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.HTTPHandler {
	return []common.HTTPHandler{
		newHTTPHandler(resolveDIDEndpoint, http.MethodGet, o.resolveDIDHandler),
	}
}

// newHTTPHandler returns instance of HTTPHandler which can be used to handle http requests.
func newHTTPHandler(path, method string, handle common.HTTPRequestHandler) common.HTTPHandler {
	return &httpHandler{path: path, method: method, handle: handle}
}

// HTTPHandler contains REST API handling details which can be used to build routers.
// for http requests for given path.
type httpHandler struct {
	path   string
	method string
	handle common.HTTPRequestHandler
}

// Path returns http request path.
func (h *httpHandler) Path() string {
	return h.path
}

// Method returns http request method type.
func (h *httpHandler) Method() string {
	return h.method
}

// Handler returns http request handle func.
func (h *httpHandler) Handler() common.HTTPRequestHandler {
	return h.handle
}
