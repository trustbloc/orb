/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = log.New("discovery-rest")

// API endpoints.
const (
	wellKnownEndpoint = "/.well-known/did-orb"
	webFingerEndpoint = "/.well-known/webfinger"
	webDIDEndpoint    = "/.well-known/did.json"
)

const (
	minResolvers = "https://trustbloc.dev/ns/min-resolvers"
	witnessType  = "https://trustbloc.dev/ns/witness"
	casType      = "https://trustbloc.dev/ns/cas"
	vctType      = "https://trustbloc.dev/ns/vct"
	context      = "https://w3id.org/did/v1"
)

// New returns discovery operations.
func New(c *Config) (*Operation, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	// If the WebCAS path is empty, it'll cause certain WebFinger queries to be matched incorrectly
	if c.WebCASPath == "" {
		return nil, fmt.Errorf("webCAS path cannot be empty")
	}

	return &Operation{
		pubKey:                    c.PubKey,
		kid:                       c.KID,
		host:                      u.Host,
		verificationMethodType:    c.VerificationMethodType,
		resolutionPath:            c.ResolutionPath,
		operationPath:             c.OperationPath,
		webCASPath:                c.WebCASPath,
		baseURL:                   c.BaseURL,
		vctURL:                    c.VctURL,
		discoveryMinimumResolvers: c.DiscoveryMinimumResolvers,
		discoveryDomains:          c.DiscoveryDomains,
		discoveryVctDomains:       c.DiscoveryVctDomains,
	}, nil
}

// Operation defines handlers for discovery operations.
type Operation struct {
	pubKey                    []byte
	kid                       string
	host                      string
	verificationMethodType    string
	resolutionPath            string
	operationPath             string
	webCASPath                string
	baseURL                   string
	vctURL                    string
	discoveryDomains          []string
	discoveryVctDomains       []string
	discoveryMinimumResolvers int
}

// Config defines configuration for discovery operations.
type Config struct {
	PubKey                    []byte
	KID                       string
	VerificationMethodType    string
	ResolutionPath            string
	OperationPath             string
	WebCASPath                string
	BaseURL                   string
	VctURL                    string
	DiscoveryDomains          []string
	DiscoveryVctDomains       []string
	DiscoveryMinimumResolvers int
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.HTTPHandler {
	return []common.HTTPHandler{
		newHTTPHandler(wellKnownEndpoint, http.MethodGet, o.wellKnownHandler),
		newHTTPHandler(webFingerEndpoint, http.MethodGet, o.webFingerHandler),
		newHTTPHandler(webDIDEndpoint, http.MethodGet, o.webDIDHandler),
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
		ResolutionEndpoint: fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath),
		OperationEndpoint:  fmt.Sprintf("%s%s", o.baseURL, o.operationPath),
	}, http.StatusOK)
}

// webDIDHandler swagger:route Get /.well-known/did.json discovery wellKnownDIDReq
//
// webDIDHandler.
//
// Responses:
//    default: genericError
//        200: wellKnownDIDResp
func (o *Operation) webDIDHandler(rw http.ResponseWriter, r *http.Request) {
	ID := "did:web:" + o.host

	writeResponse(rw, &RawDoc{
		Context: context,
		ID:      ID,
		VerificationMethod: []verificationMethod{{
			ID:              ID + "#" + o.kid,
			Controller:      ID,
			Type:            o.verificationMethodType,
			PublicKeyBase58: base58.Encode(o.pubKey),
		}},
		Authentication:       []string{ID + "#" + o.kid},
		AssertionMethod:      []string{ID + "#" + o.kid},
		CapabilityDelegation: []string{ID + "#" + o.kid},
		CapabilityInvocation: []string{ID + "#" + o.kid},
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

	o.writeResponseForResourceRequest(rw, queryValue[0])
}

func (o *Operation) writeResponseForResourceRequest(rw http.ResponseWriter, resource string) { //nolint:funlen
	switch {
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath):
		resp := &WebFingerResponse{
			Subject:    resource,
			Properties: map[string]interface{}{minResolvers: o.discoveryMinimumResolvers},
			Links: []WebFingerLink{
				{Rel: "self", Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, WebFingerLink{
				Rel:  "alternate",
				Href: fmt.Sprintf("%s%s", v, o.resolutionPath),
			})
		}

		writeResponse(rw, resp, http.StatusOK)
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.operationPath):
		resp := &WebFingerResponse{
			Subject: resource,
			Links: []WebFingerLink{
				{Rel: "self", Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, WebFingerLink{
				Rel:  "alternate",
				Href: fmt.Sprintf("%s%s", v, o.operationPath),
			})
		}

		writeResponse(rw, resp, http.StatusOK)
	case strings.HasPrefix(resource, fmt.Sprintf("%s%s", o.baseURL, o.webCASPath)):
		o.handleWebCASQuery(rw, resource)
	case strings.HasPrefix(resource, fmt.Sprintf("%s%s", o.baseURL, "/services/orb")):
		o.handleWitnessQuery(rw, resource)
	case resource == o.baseURL:
		resp := &WebFingerResponse{
			Subject: o.baseURL,
			Properties: map[string]interface{}{
				witnessType:  fmt.Sprintf("%s/services/orb", o.baseURL),
				casType:      fmt.Sprintf("%s%s", o.baseURL, o.webCASPath),
				minResolvers: o.discoveryMinimumResolvers,
				vctType:      fmt.Sprintf("%s/vct", o.baseURL),
			},
			Links: []WebFingerLink{
				{Rel: "self", Href: fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath)},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, WebFingerLink{
				Rel:  "alternate",
				Href: fmt.Sprintf("%s%s", v, o.resolutionPath),
			})
		}

		writeResponse(rw, resp, http.StatusOK)

	default:
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("resource %s not found", resource))
	}
}

func (o *Operation) handleWebCASQuery(rw http.ResponseWriter, resource string) {
	resourceSplitBySlash := strings.Split(resource, "/")

	cid := resourceSplitBySlash[len(resourceSplitBySlash)-1]

	resp := &WebFingerResponse{
		Subject: resource,
		Links: []WebFingerLink{
			{Rel: "self", Type: "application/ld+json", Href: resource},
			{Rel: "working-copy", Type: "application/ld+json", Href: fmt.Sprintf("%s/cas/%s", o.baseURL, cid)},
		},
	}

	for _, v := range o.discoveryDomains {
		resp.Links = append(resp.Links,
			WebFingerLink{
				Rel: "working-copy", Type: "application/ld+json", Href: fmt.Sprintf("%s/cas/%s", v, cid),
			})
	}

	writeResponse(rw, resp, http.StatusOK)
}

func (o *Operation) handleWitnessQuery(rw http.ResponseWriter, resource string) {
	resp := &WebFingerResponse{
		Subject: resource,
		Links: []WebFingerLink{
			{Rel: "self", Type: "application/ld+json", Href: fmt.Sprintf("%s/services/orb", o.baseURL)},
		},
	}

	writeResponse(rw, resp, http.StatusOK)
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
func writeResponse(rw http.ResponseWriter, v interface{}, status int) { // nolint: unparam
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
