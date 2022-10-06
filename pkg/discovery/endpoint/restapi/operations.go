/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	ariesmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/multiformats/go-multibase"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/document/util"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/multihash"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
	"github.com/trustbloc/orb/pkg/vct"
	"github.com/trustbloc/orb/pkg/webfinger/model"
)

var logger = log.New("discovery-rest")

const (
	wellKnownEndpoint = "/.well-known/did-orb"
	// WebFingerEndpoint is the endpoint for WebFinger calls.
	WebFingerEndpoint = "/.well-known/webfinger"
	hostMetaEndpoint  = "/.well-known/host-meta"
	// HostMetaJSONEndpoint is the endpoint for getting the host-meta document.
	HostMetaJSONEndpoint  = "/.well-known/host-meta.json"
	webDIDEndpoint        = "/.well-known/did.json"
	orbWebDIDFileEndpoint = "/scid/{id}/did.json"
	nodeInfoEndpoint      = "/.well-known/nodeinfo"

	selfRelation      = "self"
	alternateRelation = "alternate"
	viaRelation       = "via"
	serviceRelation   = "service"
	vctRelation       = "vct"

	ldJSONType    = "application/ld+json"
	jrdJSONType   = "application/jrd+json"
	didLDJSONType = "application/did+ld+json"
	// ActivityJSONType represents a link type that points to an ActivityPub endpoint.
	ActivityJSONType = "application/activity+json"

	nodeInfoV2_0Schema = "http://nodeinfo.diaspora.software/ns/schema/2.0"
	nodeInfoV2_1Schema = "http://nodeinfo.diaspora.software/ns/schema/2.1"
)

const (
	minResolvers             = "https://trustbloc.dev/ns/min-resolvers"
	contextDID               = "https://w3id.org/did/v1"
	contextDIDConfig         = "https://identity.foundation/.well-known/did-configuration/v1"
	serviceTypeLinkedDomains = "LinkedDomains"
	serviceID                = "activity-pub"
)

type cas interface {
	Read(address string) ([]byte, error)
}

type anchorLinkStore interface {
	GetLinks(anchorHash string) ([]*url.URL, error)
}

type anchorInfoRetriever interface {
	GetAnchorInfo(resource string) (*AnchorInfo, error)
}

type webfingerClient interface {
	GetLedgerType(domain string) (string, error)
}

type logEndpointRetriever interface {
	GetLogEndpoint() (string, error)
}

type webResolver interface {
	ResolveDocument(id string) (*document.ResolutionResult, error)
}

// New returns discovery operations.
func New(c *Config, p *Providers) (*Operation, error) {
	// If the WebCAS path is empty, it'll cause certain WebFinger queries to be matched incorrectly
	if c.WebCASPath == "" {
		return nil, fmt.Errorf("webCAS path cannot be empty")
	}

	domainWithPort := strings.ReplaceAll(c.ServiceEndpointURL.Host, ":", "%3A")

	serviceID := c.ServiceID

	if serviceID == nil {
		serviceID = c.ServiceEndpointURL
	}

	return &Operation{
		pubKeys:                   c.PubKeys,
		httpSignPubKeys:           c.HTTPSignPubKeys,
		resolutionPath:            c.ResolutionPath,
		operationPath:             c.OperationPath,
		webCASPath:                c.WebCASPath,
		baseURL:                   fmt.Sprintf("%s://%s", c.ServiceEndpointURL.Scheme, c.ServiceEndpointURL.Host),
		discoveryMinimumResolvers: c.DiscoveryMinimumResolvers,
		discoveryDomains:          c.DiscoveryDomains,
		serviceEndpointURL:        c.ServiceEndpointURL,
		serviceID:                 serviceID,
		anchorInfoRetriever:       NewAnchorInfoRetriever(p.ResourceRegistry),
		logEndpointRetriever:      p.LogEndpointRetriever,
		cas:                       p.CAS,
		anchorStore:               p.AnchorLinkStore,
		wfClient:                  p.WebfingerClient,
		webResolver:               p.WebResolver,
		domainWithPort:            domainWithPort,
	}, nil
}

// PublicKey public key.
type PublicKey struct {
	ID    string
	Value []byte
	Type  kms.KeyType
}

// Operation defines handlers for discovery operations.
type Operation struct {
	anchorInfoRetriever
	logEndpointRetriever
	webResolver

	pubKeys, httpSignPubKeys  []PublicKey
	resolutionPath            string
	operationPath             string
	webCASPath                string
	baseURL                   string
	discoveryDomains          []string
	discoveryMinimumResolvers int
	cas                       cas
	anchorStore               anchorLinkStore
	wfClient                  webfingerClient
	serviceEndpointURL        *url.URL
	serviceID                 *url.URL
	domainWithPort            string
}

// Config defines configuration for discovery operations.
type Config struct {
	PubKeys                   []PublicKey
	HTTPSignPubKeys           []PublicKey
	VerificationMethodType    string
	ResolutionPath            string
	OperationPath             string
	WebCASPath                string
	DiscoveryDomains          []string
	DiscoveryMinimumResolvers int
	ServiceID                 *url.URL
	ServiceEndpointURL        *url.URL
}

// Providers defines the providers for discovery operations.
type Providers struct {
	ResourceRegistry     *registry.Registry
	CAS                  cas
	AnchorLinkStore      anchorLinkStore
	WebfingerClient      webfingerClient
	LogEndpointRetriever logEndpointRetriever
	WebResolver          webResolver
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.HTTPHandler {
	handlers := []common.HTTPHandler{
		newHTTPHandler(wellKnownEndpoint, o.wellKnownHandler),
		newHTTPHandler(WebFingerEndpoint, o.webFingerHandler),
		newHTTPHandler(hostMetaEndpoint, o.hostMetaHandler),
		newHTTPHandler(HostMetaJSONEndpoint, o.hostMetaJSONHandler),
		newHTTPHandler(webDIDEndpoint, o.webDIDHandler),
		newHTTPHandler(nodeInfoEndpoint, o.nodeInfoHandler),
		newHTTPHandler(orbWebDIDFileEndpoint, o.orbWebDIDFileHandler),
	}

	// Only expose a service DID endpoint if the service ID is configured to be a DID.
	if util.IsDID(o.serviceID.String()) {
		handlers = append(handlers, newHTTPHandler(fmt.Sprintf("%s/did.json", o.serviceEndpointURL.Path),
			o.serviceWebDIDHandler))
	}

	return handlers
}

// wellKnownHandler swagger:route Get /.well-known/did-orb discovery wellKnownReq
//
// wellKnownHandler.
//
// Responses:
// default: genericError
// 200: wellKnownResp
func (o *Operation) wellKnownHandler(rw http.ResponseWriter, r *http.Request) {
	writeResponse(rw, &WellKnownResponse{
		ResolutionEndpoint: fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath),
		OperationEndpoint:  fmt.Sprintf("%s%s", o.baseURL, o.operationPath),
	})
}

func (o *Operation) orbWebDIDFileHandler(rw http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	did := fmt.Sprintf("did:web:%s:scid:%s", o.domainWithPort, id)

	result, err := o.webResolver.ResolveDocument(did)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Debug("Web resource not found", log.WithID(id))

			writeErrorResponse(rw, http.StatusNotFound, "resource not found")
		} else {
			logger.Warn("Error returning web resource", log.WithID(id), log.WithError(err))

			writeErrorResponse(rw, http.StatusInternalServerError, "error retrieving resource")
		}

		return
	}

	writeResponse(rw, result.Document)
}

// webDIDHandler swagger:route Get /.well-known/did.json discovery wellKnownDIDReq
//
// webDIDHandler.
//
// Responses:
// default: genericError
// 200: wellKnownDIDResp
func (o *Operation) webDIDHandler(rw http.ResponseWriter, r *http.Request) {
	o.handleDIDWeb("did:web:"+o.serviceEndpointURL.Host, o.pubKeys, rw, true, false)
}

// serviceWebDIDHandler swagger:route Get /services/orb/did.json discovery serviceDIDReq
//
// Responses:
// default: genericError
// 200: wellKnownDIDResp
func (o *Operation) serviceWebDIDHandler(rw http.ResponseWriter, r *http.Request) {
	o.handleDIDWeb(o.serviceID.String(), o.httpSignPubKeys, rw, false, true)
}

func (o *Operation) handleDIDWeb(did string, pubKeys []PublicKey, rw http.ResponseWriter,
	includeVerificationRelationships, includeService bool) {
	rawDoc := &ariesdid.Doc{ID: did}

	for _, key := range pubKeys {
		if err := populateVerificationMethod(rawDoc, did, key, includeVerificationRelationships); err != nil {
			writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

			return
		}
	}

	contexts := []string{contextDID}

	if includeService {
		contexts = append(contexts, contextDIDConfig)

		rawDoc.Service = []ariesdid.Service{
			{
				ID:              fmt.Sprintf("%s#%s", did, serviceID),
				Type:            serviceTypeLinkedDomains,
				ServiceEndpoint: ariesmodel.NewDIDCoreEndpoint([]string{o.baseURL}),
			},
		}
	}

	rawDoc.Context = contexts

	bytes, err := rawDoc.JSONBytes()
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	if _, err = rw.Write(bytes); err != nil {
		log.WriteResponseBodyError(logger, err)
	}
}

//nolint:cyclop
func populateVerificationMethod(rawDoc *ariesdid.Doc, did string, key PublicKey,
	includeVerificationRelationships bool) error {
	var vm *ariesdid.VerificationMethod

	switch {
	case key.Type == kms.ED25519:
		vm = ariesdid.NewVerificationMethodFromBytesWithMultibase(did+"#"+key.ID,
			"Ed25519VerificationKey2020", did, key.Value, multibase.Base58BTC)
	case key.Type == kms.ECDSAP256IEEEP1363 || key.Type == kms.ECDSAP384IEEEP1363 ||
		key.Type == kms.ECDSAP521IEEEP1363 || key.Type == kms.ECDSAP256DER ||
		key.Type == kms.ECDSAP384TypeDER || key.Type == kms.ECDSAP521TypeDER:
		jwk, err := jwksupport.PubKeyBytesToJWK(key.Value, key.Type)
		if err != nil {
			return err
		}

		vm, err = ariesdid.NewVerificationMethodFromJWK(did+"#"+key.ID, "JsonWebKey2020", did, jwk)
		if err != nil {
			return err
		}
	}

	rawDoc.VerificationMethod = append(rawDoc.VerificationMethod, *vm)

	if includeVerificationRelationships {
		rawDoc.Authentication = append(rawDoc.Authentication,
			*ariesdid.NewReferencedVerification(vm, ariesdid.Authentication))
		rawDoc.AssertionMethod = append(rawDoc.AssertionMethod,
			*ariesdid.NewReferencedVerification(vm, ariesdid.AssertionMethod))
		rawDoc.CapabilityDelegation = append(rawDoc.CapabilityDelegation,
			*ariesdid.NewReferencedVerification(vm, ariesdid.CapabilityDelegation))
		rawDoc.CapabilityInvocation = append(rawDoc.CapabilityInvocation,
			*ariesdid.NewReferencedVerification(vm, ariesdid.CapabilityInvocation))
	}

	return nil
}

// webFingerHandler swagger:route Get /.well-known/webfinger discovery webFingerReq
//
// webFingerHandler.
//
// Responses:
// default: genericError
// 200: webFingerResp
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
// Returns the NodeInfo endpoints that may be queried to provide general information about an Orb server.
//
// Responses:
// default: genericError
// 200: wellKnownNodeInfoResp
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
	})
}

func (o *Operation) writeResponseForResourceRequest(rw http.ResponseWriter, resource string) {
	switch {
	case resource == o.baseURL || resource == o.serviceEndpointURL.String():
		o.handleDomainQuery(rw, resource)
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.resolutionPath):
		resp := &JRD{
			Subject:    resource,
			Properties: map[string]interface{}{minResolvers: o.discoveryMinimumResolvers},
			Links: []Link{
				{Rel: selfRelation, Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, Link{
				Rel:  alternateRelation,
				Href: fmt.Sprintf("%s%s", v, o.resolutionPath),
			})
		}

		writeResponse(rw, resp)
	case resource == fmt.Sprintf("%s%s", o.baseURL, o.operationPath):
		resp := &JRD{
			Subject: resource,
			Links: []Link{
				{Rel: selfRelation, Href: resource},
			},
		}

		for _, v := range o.discoveryDomains {
			resp.Links = append(resp.Links, Link{
				Rel:  alternateRelation,
				Href: fmt.Sprintf("%s%s", v, o.operationPath),
			})
		}

		writeResponse(rw, resp)
	case strings.HasPrefix(resource, fmt.Sprintf("%s%s", o.baseURL, o.webCASPath)):
		o.handleWebCASQuery(rw, resource)
	case strings.HasPrefix(resource, "did:orb:"):
		o.handleDIDOrbQuery(rw, resource)
	// TODO (#536): Support resources other than did:orb.
	default:
		writeErrorResponse(rw, http.StatusNotFound, fmt.Sprintf("resource %s not found,", resource))
	}
}

func (o *Operation) handleDIDOrbQuery(rw http.ResponseWriter, resource string) {
	anchorInfo, err := o.GetAnchorInfo(resource)
	if err != nil {
		logger.Warn("Error getting anchor info", log.WithResource(resource), log.WithError(err))

		writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to get info on %s: %s", resource, err.Error()))

		return
	}

	did := getCanonicalDID(resource, anchorInfo.CanonicalReference)

	resp := &JRD{
		Properties: map[string]interface{}{
			"https://trustbloc.dev/ns/anchor-origin": anchorInfo.AnchorOrigin,
			minResolvers:                             o.discoveryMinimumResolvers,
		},
		Links: []Link{
			{
				Rel:  selfRelation,
				Type: didLDJSONType,
				Href: fmt.Sprintf("%s%s%s", o.baseURL, "/sidetree/v1/identifiers/", did),
			},
			{
				Rel:  viaRelation,
				Type: ldJSONType,
				Href: anchorInfo.AnchorURI,
			},
			{
				Rel:  serviceRelation,
				Type: ActivityJSONType,
				Href: o.serviceEndpointURL.String(),
			},
		},
	}

	for _, discoveryDomain := range o.appendAlternateDomains(o.discoveryDomains, anchorInfo.AnchorURI) {
		resp.Links = append(resp.Links, Link{
			Rel:  alternateRelation,
			Type: didLDJSONType,
			Href: fmt.Sprintf("%s%s%s", discoveryDomain, "/sidetree/v1/identifiers/", did),
		})
	}

	writeResponse(rw, resp)
}

func (o *Operation) handleDomainQuery(rw http.ResponseWriter, resource string) {
	resp := &JRD{
		Subject: resource,
	}

	resp.Links = append(resp.Links, Link{
		Rel:  selfRelation,
		Type: jrdJSONType,
		Href: resource,
	})

	logURL, err := o.logEndpointRetriever.GetLogEndpoint()
	if err != nil && !errors.Is(err, vct.ErrDisabled) && !errors.Is(err, vct.ErrLogEndpointNotConfigured) {
		logger.Warn("Error retrieving log endpoint", log.WithError(err))

		writeErrorResponse(rw, http.StatusInternalServerError, "error retrieving log endpoint")

		return
	}

	if logURL != "" {
		resp.Links = append(resp.Links, Link{
			Rel:  vctRelation,
			Type: jrdJSONType,
			Href: logURL,
		})

		lt, err := o.wfClient.GetLedgerType(logURL)
		if err != nil {
			if errors.Is(err, model.ErrResourceNotFound) {
				writeResponse(rw, resp)
			} else {
				logger.Warn("Error retrieving ledger type from VCT", log.WithHRef(logURL), log.WithError(err))

				writeErrorResponse(rw, http.StatusInternalServerError, "error retrieving ledger type from VCT")
			}

			return
		}

		resp.Properties = map[string]interface{}{
			command.LedgerType: lt,
		}
	}

	writeResponse(rw, resp)
}

func (o *Operation) handleWebCASQuery(rw http.ResponseWriter, resource string) {
	resourceSplitBySlash := strings.Split(resource, "/")

	cid := resourceSplitBySlash[len(resourceSplitBySlash)-1]

	if cid == "" {
		writeErrorResponse(rw, http.StatusBadRequest, "resource ID not provided in request")

		return
	}

	// Ensure that the CID is resolvable.
	_, err := o.cas.Read(cid)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Debug("CAS resource not found", log.WithCID(cid))

			writeErrorResponse(rw, http.StatusNotFound, "resource not found")
		} else {
			logger.Warn("Error returning CAS resource", log.WithCID(cid), log.WithError(err))

			writeErrorResponse(rw, http.StatusInternalServerError, "error retrieving resource")
		}

		return
	}

	resp := &JRD{
		Subject: resource,
		Links: []Link{
			{Rel: selfRelation, Type: ldJSONType, Href: resource},
		},
	}

	var refs []string

	// Add the references from the configured discovery domains.
	for _, v := range o.discoveryDomains {
		refs = append(refs, fmt.Sprintf("%s/cas/%s", v, cid))
	}

	// Add references from the anchor link storage.
	for _, ref := range o.appendAlternateAnchorRefs(refs, cid) {
		resp.Links = append(resp.Links,
			Link{
				Rel: alternateRelation, Type: ldJSONType, Href: ref,
			})
	}

	writeResponse(rw, resp)
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
				Href: o.serviceEndpointURL.String(),
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

	writeResponse(rw, resp)
}

func (o *Operation) appendAlternateDomains(domains []string, anchorURI string) []string {
	parser := hashlink.New()

	anchorInfo, err := parser.ParseHashLink(anchorURI)
	if err != nil {
		logger.Info("Error parsing hashlink for anchor URI", log.WithAnchorURIString(anchorURI), log.WithError(err))

		return domains
	}

	alternates, err := o.anchorStore.GetLinks(anchorInfo.ResourceHash)
	if err != nil {
		logger.Info("Error getting alternate links for anchor URI", log.WithAnchorURIString(anchorURI), log.WithError(err))

		return domains
	}

	for _, domain := range getDomainsFromHashLinks(alternates) {
		if !contains(domains, domain) {
			domains = append(domains, domain)
		}
	}

	return domains
}

func (o *Operation) appendAlternateAnchorRefs(refs []string, cidOrHash string) []string {
	hash, e := multihash.CIDToMultihash(cidOrHash)
	if e != nil {
		hash = cidOrHash
	} else if hash != cidOrHash {
		logger.Debug("Converted CID to multihash", log.WithCID(cidOrHash), log.WithMultihash(hash))
	}

	alternates, err := o.anchorStore.GetLinks(hash)
	if err != nil {
		// Not fatal.
		logger.Warn("Error retrieving additional links for resource", log.WithMultihash(hash), log.WithError(err))

		return refs
	}

	parser := hashlink.New()

	for _, hl := range alternates {
		hlInfo, err := parser.ParseHashLink(hl.String())
		if err != nil {
			logger.Warn("Error parsing hashlink", log.WithHashlinkURI(hl), log.WithError(err))

			continue
		}

		for _, l := range hlInfo.Links {
			if !contains(refs, l) {
				refs = append(refs, l)
			}
		}
	}

	return refs
}

func getDomainsFromHashLinks(hashLinks []*url.URL) []string {
	parser := hashlink.New()

	var domains []string

	for _, hl := range hashLinks {
		hlInfo, err := parser.ParseHashLink(hl.String())
		if err != nil {
			logger.Warn("Error parsing hashlink", log.WithHashlinkURI(hl), log.WithError(err))

			continue
		}

		for _, l := range hlInfo.Links {
			link, err := url.Parse(l)
			if err != nil {
				logger.Warn("Error parsing additional anchor link for hash",
					log.WithLink(l), log.WithHash(hlInfo.ResourceHash), log.WithError(err))

				continue
			}

			if !strings.EqualFold(link.Scheme, "https") {
				continue
			}

			domain := fmt.Sprintf("https://%s", link.Host)

			if !contains(domains, domain) {
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// writeErrorResponse write error resp.
func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.Header().Add("Content-Type", "application/json")
	rw.WriteHeader(status)

	err := json.NewEncoder(rw).Encode(ErrorResponse{
		Message: msg,
	})
	if err != nil {
		logger.Error("Unable to send error message", log.WithError(err))
	}
}

// writeResponse writes response.
func writeResponse(rw http.ResponseWriter, v interface{}) {
	rw.Header().Add("Content-Type", "application/json")

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		log.WriteResponseBodyError(logger, err)
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
	return fmt.Sprintf("%s%s", baseURL, "/services/orb") // FIXME: Should not hard-code /services/orb.
}

func contains(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}

	return false
}

func getCanonicalDID(resource, canonicalRef string) string {
	if canonicalRef != "" {
		i := strings.LastIndex(resource, ":")
		if i > 0 {
			return fmt.Sprintf("did:orb:%s:%s", canonicalRef, resource[i+1:])
		}
	}

	return resource
}
