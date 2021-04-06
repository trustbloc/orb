/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = log.New("discovery-rest")

// API endpoints.
const (
	wellKnownEndpoint = "/.well-known/did-orb"
)

type wellKnowResp struct {
	ResolutionEndpoint string `json:"resolutionEndpoint"`
	OperationEndpoint  string `json:"operationEndpoint"`
}

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
	}
}

func (o *Operation) wellKnownHandler(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&wellKnowResp{
		ResolutionEndpoint: o.resolutionEndpoint,
		OperationEndpoint:  o.operationEndpoint,
	})
	if err != nil {
		logger.Errorf("well known response failure, %s", err)
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
