/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = log.New("discovery-rest")

// API endpoints.
const (
	wellKnownEndpoint = "/.well-known/did-orb"
	webFingerEndpoint = "/.well-known/webfinger"
)

const (
	minResolvers      = "https://trustbloc.dev/ns/min-resolvers"
	minResolversValue = 2 // TODO need to be configurable
)

// New returns discovery operations.
func New(c *Config) *Operation {
	return &Operation{
		resolutionEndpoint: fmt.Sprintf("%s%s", c.BaseURL, c.ResolutionPath),
		operationEndpoint:  fmt.Sprintf("%s%s", c.BaseURL, c.OperationPath),
	}
}

// Operation defines handlers for discovery operations.
type Operation struct {
	resolutionEndpoint string
	operationEndpoint  string
}

// Config defines configuration for discovery operations.
type Config struct {
	ResolutionPath string
	OperationPath  string
	BaseURL        string
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.HTTPHandler {
	return []common.HTTPHandler{
		newHTTPHandler(wellKnownEndpoint, http.MethodGet, o.wellKnownHandler),
		newHTTPHandler(webFingerEndpoint, http.MethodGet, o.webFingerHandler),
	}
}

// wellKnownHandler swagger:route Get /.well-known/did-orb discovery wellKnownReq
//
// wellKnownHandler.
//
// Responses:
//    default: genericError
//        200: wellKnownResp
func (o *Operation) wellKnownHandler(rw http.ResponseWriter, r *http.Request) {
	writeResponse(rw, &WellKnownResponse{
		ResolutionEndpoint: o.resolutionEndpoint,
		OperationEndpoint:  o.operationEndpoint,
	}, http.StatusOK)
}

// webFingerHandler swagger:route Get /.well-known/webfinger discovery webFingerReq
//
// webFingerHandler.
//
// Responses:
//    default: genericError
//        200: webFingerResp
func (o *Operation) webFingerHandler(rw http.ResponseWriter, r *http.Request) {
	queryValue := r.URL.Query()["resource"]
	if len(queryValue) == 0 {
		writeErrorResponse(rw, http.StatusBadRequest, "resource query string not found")

		return
	}

	resource := queryValue[0]

	switch {
	case strings.Contains(resource, o.resolutionEndpoint):
		resp := &WebFingerResponse{
			Subject:    resource,
			Properties: map[string]interface{}{minResolvers: minResolversValue},
			// TODO how to get other instances endpoints
			// https://trustbloc.github.io/did-method-orb/#example-11-client-shared-domain-discovery-response
			Links: []WebFingerLink{
				{Rel: "self", Href: resource},
			},
		}
		writeResponse(rw, resp, http.StatusOK)
	case strings.Contains(resource, o.operationEndpoint):
		resp := &WebFingerResponse{
			Subject: resource,
			// TODO how to get other instances endpoints
			// https://trustbloc.github.io/did-method-orb/#example-11-client-shared-domain-discovery-response
			Links: []WebFingerLink{
				{Rel: "self", Href: resource},
			},
		}
		writeResponse(rw, resp, http.StatusOK)
	default:
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("resource %s not found", resource))
	}
}

// writeErrorResponse write error resp.
func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})
	if err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// writeResponse writes response.
func writeResponse(rw http.ResponseWriter, v interface{}, status int) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("unable to send a response: %v", err)
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
