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

	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
)

var logger = log.New("discovery-rest")

const (
	wellKnownEndpoint = "/.well-known/did-orb"
	// WebFingerEndpoint is the endpoint for WebFinger calls.
	WebFingerEndpoint = "/.well-known/webfinger"
	hostMetaEndpoint  = "/.well-known/host-meta"
	// HostMetaJSONEndpoint is the endpoint for getting the host-meta document.
	HostMetaJSONEndpoint = "/.well-known/host-meta.json"
	webDIDEndpoint       = "/.well-known/did.json"
	nodeInfoEndpoint     = "/.well-known/nodeinfo"

	selfRelation      = "self"
	alternateRelation = "alternate"
	viaRelation       = "via"
	serviceRelation   = "service"

	ldJSONType    = "application/ld+json"
	jrdJSONType   = "application/jrd+json"
	didLDJSONType = "application/did+ld+json"
	// ActivityJSONType represents a link type that points to an ActivityPub endpoint.
	ActivityJSONType = "application/activity+json"

	nodeInfoV2_0Schema = "http://nodeinfo.diaspora.software/ns/schema/2.0"
	nodeInfoV2_1Schema = "http://nodeinfo.diaspora.software/ns/schema/2.1"
)

const (
	minResolvers = "https://trustbloc.dev/ns/min-resolvers"
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
		resourceRegistry:          c.ResourceRegistry,
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
	resourceRegistry          *registry.Registry
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
	ResourceRegistry          *registry.Registry
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.HTTPHandler {
	return []common.HTTPHandler{
		newHTTPHandler(wellKnownEndpoint, o.wellKnownHandler),
		newHTTPHandler(WebFingerEndpoint, o.webFingerHandler),
		newHTTPHandler(hostMetaEndpoint, o.hostMetaHandler),
		newHTTPHandler(HostMetaJSONEndpoint, o.hostMetaJSONHandler),
		newHTTPHandler(webDIDEndpoint, o.webDIDHandler),
		newHTTPHandler(nodeInfoEndpoint, o.nodeInfoHandler),
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

// nodeInfoHandler swagger:route Get /.well-known/nodeinfo discovery wellKnownNodeInfoReq
//
// webDIDHandler.
//
// Responses:
//    default: genericError
//        200: wellKnownNodeInfoResp
func (o *Operation) nodeInfoHandler(rw http.ResponseWriter, r *http.Request) {
	writeResponse(rw, &JRD{
		Links: []Link{
			{
				Rel:  nodeInfoV2_0Schema,
				Href: fmt.Sprintf("%s/nodeinfo/2.0", o.baseURL),
			},
			{
				Rel:  nodeInfoV2_1Schema,
				Href: fmt.Sprintf("%s/nodeinfo/2.1", o.baseURL),
			},
		},
	}, http.StatusOK)
}

//nolint:funlen,gocyclo,cyclop
func (o *Operation) writeResponseForResourceRequest(rw http.ResponseWriter, resource string) {
	switch {
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath):
		resp := &JRD{
			Subject:    resource,
			Properties: map[string]interface{}{minResolvers: o.discoveryMinimumResolvers},
			Links: []Link{
				{Rel: "self", Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, Link{
				Rel:  "alternate",
				Href: fmt.Sprintf("%s%s", v, o.resolutionPath),
			})
		}

		writeResponse(rw, resp, http.StatusOK)
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.operationPath):
		resp := &JRD{
			Subject: resource,
			Links: []Link{
				{Rel: "self", Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, Link{
				Rel:  "alternate",
				Href: fmt.Sprintf("%s%s", v, o.operationPath),
			})
		}

		writeResponse(rw, resp, http.StatusOK)
	case strings.HasPrefix(resource, fmt.Sprintf("%s%s", o.baseURL, o.webCASPath)):
		o.handleWebCASQuery(rw, resource)
	case strings.HasPrefix(resource, "did:orb:"):
		// TODO (#536): Support resources other than did:orb.
		// TODO (#537): Show IPFS alternates if configured.
		metadata, err := o.resourceRegistry.GetResourceInfo(resource)
		if err != nil {
			writeErrorResponse(rw, http.StatusInternalServerError,
				fmt.Sprintf("failed to get info on %s: %s", resource, err.Error()))

			return
		}

		anchorOrigin, ok := metadata[registry.AnchorOriginProperty]
		if !ok {
			writeErrorResponse(rw, http.StatusBadRequest, "anchor origin property missing from metadata")

			return
		}

		anchorURIRaw, ok := metadata[registry.AnchorURIProperty]
		if !ok {
			writeErrorResponse(rw, http.StatusBadRequest, "anchor URI property missing from metadata")

			return
		}

		anchorURI, ok := anchorURIRaw.(string)
		if !ok {
			writeErrorResponse(rw, http.StatusBadRequest, "anchor URI could not be asserted as a string")

			return
		}

		resp := &JRD{
			Properties: map[string]interface{}{
				"https://trustbloc.dev/ns/anchor-origin": anchorOrigin,
				minResolvers:                             o.discoveryMinimumResolvers,
			},
			Links: []Link{
				{
					Rel:  selfRelation,
					Type: didLDJSONType,
					Href: fmt.Sprintf("%s%s%s", o.baseURL, "/sidetree/v1/identifiers/", resource),
				},
				{
					Rel:  viaRelation,
					Type: ldJSONType,
					Href: anchorURI,
				},
				{
					Rel:  serviceRelation,
					Type: ActivityJSONType,
					Href: constructActivityPubURL(o.baseURL),
				},
			},
		}

		for _, discoveryDomain := range o.discoveryDomains {
			resp.Links = append(resp.Links, Link{
				Rel:  alternateRelation,
				Type: didLDJSONType,
				Href: fmt.Sprintf("%s%s%s", discoveryDomain, "/sidetree/v1/identifiers/", resource),
			})
		}

		writeResponse(rw, resp, http.StatusOK)
	default:
		writeErrorResponse(rw, http.StatusNotFound, fmt.Sprintf("resource %s not found,", resource))
	}
}

func (o *Operation) handleWebCASQuery(rw http.ResponseWriter, resource string) {
	resourceSplitBySlash := strings.Split(resource, "/")

	cid := resourceSplitBySlash[len(resourceSplitBySlash)-1]

	resp := &JRD{
		Subject: resource,
		Links: []Link{
			{Rel: "self", Type: "application/ld+json", Href: resource},
			{Rel: "working-copy", Type: "application/ld+json", Href: fmt.Sprintf("%s/cas/%s", o.baseURL, cid)},
		},
	}

	for _, v := range o.discoveryDomains {
		resp.Links = append(resp.Links,
			Link{
				Rel: "working-copy", Type: "application/ld+json", Href: fmt.Sprintf("%s/cas/%s", v, cid),
			})
	}

	writeResponse(rw, resp, http.StatusOK)
}

func (o *Operation) hostMetaHandler(rw http.ResponseWriter, r *http.Request) {
	acceptedFormat := r.Header.Get("Accept")

	// TODO (#546): support XRD as required by the spec: https://datatracker.ietf.org/doc/html/rfc6415#section-3
	if acceptedFormat != "application/json" {
		writeErrorResponse(rw, http.StatusBadRequest,
			`the Accept header must be set to application/json to use this endpoint`)

		return
	}

	o.respondWithHostMetaJSON(rw)
}

func (o *Operation) hostMetaJSONHandler(rw http.ResponseWriter, _ *http.Request) {
	o.respondWithHostMetaJSON(rw)
}

func (o *Operation) respondWithHostMetaJSON(rw http.ResponseWriter) {
	resp := &JRD{
		Links: []Link{
			{
				Rel:      selfRelation,
				Type:     jrdJSONType,
				Template: fmt.Sprintf("%s%s%s", o.baseURL, WebFingerEndpoint, "?resource={uri}"),
			},
			{
				Rel:  selfRelation,
				Type: ActivityJSONType,
				Href: constructActivityPubURL(o.baseURL),
			},
		},
	}

	for _, discoveryDomain := range o.discoveryDomains {
		resp.Links = append(resp.Links, Link{
			Rel:      alternateRelation,
			Type:     jrdJSONType,
			Template: fmt.Sprintf("%s%s%s", discoveryDomain, WebFingerEndpoint, "?resource={uri}"),
		}, Link{
			Rel:  alternateRelation,
			Type: ActivityJSONType,
			Href: constructActivityPubURL(discoveryDomain),
		})
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
func newHTTPHandler(path string, handle common.HTTPRequestHandler) common.HTTPHandler {
	return &httpHandler{path: path, handle: handle}
}

// HTTPHandler contains REST API handling details which can be used to build routers.
// for http requests for given path.
type httpHandler struct {
	path   string
	handle common.HTTPRequestHandler
}

// Path returns http request path.
func (h *httpHandler) Path() string {
	return h.path
}

// Method returns http request method type.
func (h *httpHandler) Method() string {
	return http.MethodGet
}

// Handler returns http request handle func.
func (h *httpHandler) Handler() common.HTTPRequestHandler {
	return h.handle
}

func constructActivityPubURL(baseURL string) string {
	return fmt.Sprintf("%s%s", baseURL, "/services/orb")
}
