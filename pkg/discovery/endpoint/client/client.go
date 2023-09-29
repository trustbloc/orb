/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package client implements endpoint client
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-go/pkg/docutil"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/orbclient/aoprovider"
)

var logger = log.New("endpoint-client")

const (
	minResolvers         = "https://trustbloc.dev/ns/min-resolvers"
	anchorOriginProperty = "https://trustbloc.dev/ns/anchor-origin"

	serviceTypeLinkedDomains = "LinkedDomains"

	namespace  = "did:orb"
	ipfsGlobal = "https://ipfs.io"

	defaultCacheLifetime = 300 * time.Second // five minutes
	defaultCacheSize     = 100
	self                 = "self"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type casReader interface {
	Read(key string) ([]byte, error)
}

type orbClient interface {
	GetAnchorOrigin(cid, suffix string) (interface{}, error)
}

// Client fetches configs, caching results in-memory.
type Client struct {
	namespace         string
	httpClient        httpClient
	casReader         casReader
	authToken         string
	authTokenProvider authTokenProvider
	disableProofCheck bool
	publicKeyFetcher  verifiable.PublicKeyFetcher
	didWebHTTP        bool
	docLoader         ld.DocumentLoader
	orbClient         orbClient

	endpointsCache gcache.Cache
	domainCache    gcache.Cache
	cacheLifetime  time.Duration
	cacheSize      int
	vdr            vdrapi.Registry
}

type defaultHTTPClient struct{}

func (d *defaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

func (d *defaultHTTPClient) Get(context.Context, *transport.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unable to perform GET call since no transport was configured. " +
		"Use the WithHTTPClient option to configure this discovery endpoint client with a transport")
}

// New create new endpoint client.
func New(docLoader ld.DocumentLoader, casReader casReader, opts ...Option) (*Client, error) {
	configService := &Client{
		namespace: namespace, docLoader: docLoader, casReader: casReader,
		httpClient:    &defaultHTTPClient{},
		cacheLifetime: defaultCacheLifetime,
		cacheSize:     defaultCacheSize,
	}

	for _, opt := range opts {
		opt(configService)
	}

	var orbClientOpts []aoprovider.Option

	orbClientOpts = append(orbClientOpts, aoprovider.WithJSONLDDocumentLoader(docLoader))

	if configService.vdr == nil {
		// Construct a VDR that only supports did:web.
		configService.vdr = vdr.New(
			vdr.WithVDR(&webVDR{
				http:    configService.httpClient,
				useHTTP: configService.didWebHTTP,
				VDR:     web.New(),
			}),
		)
	}

	if configService.disableProofCheck {
		orbClientOpts = append(orbClientOpts, aoprovider.WithDisableProofCheck(configService.disableProofCheck))
	} else {
		if configService.publicKeyFetcher == nil {
			configService.publicKeyFetcher = verifiable.NewVDRKeyResolver(configService.vdr).PublicKeyFetcher()
		}

		orbClientOpts = append(orbClientOpts, aoprovider.WithPublicKeyFetcher(configService.publicKeyFetcher))
	}

	orbClient, err := aoprovider.New(configService.namespace, configService.casReader, orbClientOpts...)
	if err != nil {
		return nil, err
	}

	configService.orbClient = orbClient

	configService.endpointsCache = gcache.New(configService.cacheSize).
		Expiration(configService.cacheLifetime).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			return configService.getEndpoint(key.(string)) //nolint:forcetypeassert
		}).Build()

	configService.domainCache = gcache.New(configService.cacheSize).
		Expiration(configService.cacheLifetime).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			return configService.loadDomainForDID(key.(string)) //nolint:forcetypeassert
		}).Build()

	return configService, nil
}

// GetEndpoint fetches endpoints from domain, caching the value.
func (cs *Client) GetEndpoint(domain string) (*models.Endpoint, error) {
	endpoint, err := cs.endpointsCache.Get(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get key[%s] from endpoints cache: %w", domain, err)
	}

	logger.Debug("Got value from endpoints cache", logfields.WithKey(domain), logfields.WithAnchorOriginEndpoint(endpoint))

	return endpoint.(*models.Endpoint), nil //nolint:forcetypeassert
}

// GetEndpointNoCache fetches endpoints from domain bypassing the cache.
func (cs *Client) GetEndpointNoCache(domain string) (*models.Endpoint, error) {
	return cs.getEndpoint(domain)
}

// GetEndpointFromAnchorOrigin fetches endpoints from anchor origin, caching the value.
func (cs *Client) GetEndpointFromAnchorOrigin(didURI string) (*models.Endpoint, error) {
	return cs.getEndpointAnchorOrigin(didURI)
}

// ResolveDomainForDID resolves the origin domain for the given DID.
func (cs *Client) ResolveDomainForDID(id string) (string, error) {
	domain, err := cs.domainCache.Get(id)
	if err != nil {
		return "", err
	}

	return domain.(string), nil //nolint:forcetypeassert
}

func (cs *Client) getEndpoint(uri string) (*models.Endpoint, error) { //nolint:cyclop
	var domain string

	switch {
	case util.IsDID(uri):
		var err error

		domain, err = cs.ResolveDomainForDID(uri)
		if err != nil {
			return nil, fmt.Errorf("get domain from DID: %w", err)
		}
	case strings.HasPrefix(uri, "ipns://"):
		var err error

		domain, err = cs.GetDomainFromIPNS(uri)
		if err != nil {
			return nil, err
		}
	case !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://"):
		domain = "https://" + uri
	default:
		domain = uri
	}

	logger.Debug("Resolved domain from URI", logfields.WithURIString(uri), logfields.WithDomain(domain))

	var wellKnownResponse restapi.WellKnownResponse

	err := cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/did-orb", domain), &wellKnownResponse)
	if err != nil {
		return nil, err
	}

	var jrd restapi.JRD

	parsedURL, err := url.Parse(wellKnownResponse.ResolutionEndpoint)
	if err != nil {
		return nil, err
	}

	endpoint, err := cs.populateResolutionEndpoint(fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
		parsedURL.Scheme, parsedURL.Host, url.PathEscape(wellKnownResponse.ResolutionEndpoint)))
	if err != nil {
		return nil, err
	}

	err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
		parsedURL.Scheme, parsedURL.Host, url.PathEscape(wellKnownResponse.OperationEndpoint)), &jrd)
	if err != nil {
		return nil, err
	}

	for _, v := range jrd.Links {
		endpoint.OperationEndpoints = append(endpoint.OperationEndpoints, v.Href)
	}

	logger.Debug("... resolved endpoint from URI", logfields.WithURIString(uri), logfields.WithAnchorOriginEndpoint(endpoint))

	return endpoint, nil
}

// GetDomainFromIPNS get domain from ipns.
func (cs *Client) GetDomainFromIPNS(uri string) (string, error) {
	anchorOriginSplit := strings.Split(uri, "ipns://")

	var jrd restapi.JRD

	var domain string

	err := cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s/.well-known/host-meta.json", ipfsGlobal, "ipns",
		anchorOriginSplit[1]), &jrd)
	if err != nil {
		return "", err
	}

	for _, v := range jrd.Links {
		if v.Rel == self && v.Type == "application/activity+json" {
			parsedURL, err := url.Parse(v.Href)
			if err != nil {
				return "", err
			}

			domain = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

			break
		}
	}

	if domain == "" {
		return "", fmt.Errorf("couldn't find application/activity+json in ipns file")
	}

	return domain, nil
}

func (cs *Client) loadDomainForDID(id string) (string, error) {
	doc, err := cs.vdr.Resolve(id)
	if err != nil {
		return "", fmt.Errorf("resolve DID [%s]: %w", id, err)
	}

	for _, service := range doc.DIDDocument.Service { //nolint:gocritic
		if service.Type == serviceTypeLinkedDomains {
			uri, err := service.ServiceEndpoint.URI()
			if err != nil {
				return "", fmt.Errorf("invalid service endpoint for did [%s]: %w", id, err)
			}

			logger.Debug("Resolved service endpoint domain", logfields.WithDID(id), logfields.WithURIString(uri))

			return uri, nil
		}
	}

	return "", fmt.Errorf("service endpoint not found in DID document for did [%s]", id)
}

func (cs *Client) populateAnchorResolutionEndpoint(jrd *restapi.JRD) (*models.Endpoint, error) {
	endpoint := &models.Endpoint{}

	min, ok := jrd.Properties[minResolvers].(float64)
	if !ok {
		return nil, fmt.Errorf("%s property is not float64", minResolvers)
	}

	endpoint.MinResolvers = int(min)

	for _, v := range jrd.Links {
		if v.Type == "application/did+ld+json" {
			endpoint.ResolutionEndpoints = append(endpoint.ResolutionEndpoints,
				v.Href[:strings.Index(v.Href, cs.namespace)-1])
		}

		if v.Type == "application/ld+json" {
			endpoint.AnchorURI = v.Href
		}
	}

	anchorOrigin, ok := jrd.Properties[anchorOriginProperty].(string)
	if !ok {
		return nil, fmt.Errorf("%s property is not string", anchorOriginProperty)
	}

	endpoint.AnchorOrigin = anchorOrigin

	return endpoint, nil
}

func (cs *Client) populateResolutionEndpoint(webFingerURL string) (*models.Endpoint, error) { //nolint: cyclop
	var jrd restapi.JRD

	err := cs.sendRequest(nil, http.MethodGet, webFingerURL, &jrd)
	if err != nil {
		return nil, err
	}

	endpoint := &models.Endpoint{}

	min, ok := jrd.Properties[minResolvers].(float64)
	if !ok {
		return nil, fmt.Errorf("%s property is not float64", minResolvers)
	}

	endpoint.MinResolvers = int(min)

	m := make(map[string]struct{})

	for _, v := range jrd.Links {
		m[v.Href] = struct{}{}
	}

	// Fetches the configurations at each chosen link using WebFinger.
	// Validates that each well-known configuration has the same policy for n and that all of the
	// chosen links are listed in the n fetched configurations.

	for _, v := range jrd.Links {
		if v.Rel != self { //nolint: nestif
			var webFingerResp restapi.JRD

			parsedURL, err := url.Parse(v.Href)
			if err != nil {
				return nil, err
			}

			err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
				parsedURL.Scheme, parsedURL.Host, url.PathEscape(v.Href)), &webFingerResp)
			if err != nil {
				return nil, err
			}

			min, ok = webFingerResp.Properties[minResolvers].(float64)
			if !ok {
				return nil, fmt.Errorf("%s property is not float64", minResolvers)
			}

			if int(min) != endpoint.MinResolvers {
				logger.Warn("Link has different policy for min resolvers", logfields.WithHRef(v.Href))

				continue
			}

			if len(webFingerResp.Links) != len(jrd.Links) {
				logger.Warn("Number of links is different", logfields.WithHRef(v.Href))

				continue
			}

			for _, link := range webFingerResp.Links {
				if _, ok = m[link.Href]; !ok {
					logger.Warn("Link content is different", logfields.WithHRef(v.Href))

					continue
				}
			}
		}

		endpoint.ResolutionEndpoints = append(endpoint.ResolutionEndpoints, v.Href)
	}

	return endpoint, nil
}

func (cs *Client) getEndpointAnchorOrigin(didURI string) (*models.Endpoint, error) {
	cid, suffix, err := cs.getCIDAndSuffix(didURI)
	if err != nil {
		return nil, fmt.Errorf("get CID and suffix for [%s]: %w", didURI, err)
	}

	result, err := cs.orbClient.GetAnchorOrigin(cid, suffix)
	if err != nil {
		return nil, fmt.Errorf("get anchor origin for [%s]: %w", didURI, err)
	}

	anchorOrigin, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("get anchor origin didn't return string")
	}

	currentAnchorOrigin := anchorOrigin

	var currentWebFingerResponse *restapi.JRD

	for {
		jrdLatestAnchorOrigin, errGet := cs.getLatestAnchorOrigin(currentAnchorOrigin, didURI)
		if errGet != nil {
			return nil, fmt.Errorf("get latest anchor origin for [%s] - current anchor origin [%s]: %w",
				didURI, currentAnchorOrigin, errGet)
		}

		latestAnchorOrigin, ok := jrdLatestAnchorOrigin.Properties[anchorOriginProperty].(string)
		if !ok {
			return nil, fmt.Errorf("%s property is not string", anchorOriginProperty)
		}

		if latestAnchorOrigin == currentAnchorOrigin {
			currentWebFingerResponse = jrdLatestAnchorOrigin

			break
		}

		currentAnchorOrigin = latestAnchorOrigin
	}

	return cs.populateAnchorResolutionEndpoint(currentWebFingerResponse)
}

func (cs *Client) getCIDAndSuffix(didURI string) (string, string, error) {
	if !strings.HasPrefix(didURI, cs.namespace+docutil.NamespaceDelimiter) {
		return "", "", fmt.Errorf("did[%s] must start with configured namespace[%s]", didURI, cs.namespace)
	}

	cidWithHintAndSuffix := didURI[len(cs.namespace+docutil.NamespaceDelimiter):]

	parts := strings.Split(cidWithHintAndSuffix, docutil.NamespaceDelimiter)

	const minParts = 2
	if len(parts) < minParts {
		return "", "", fmt.Errorf("invalid number of parts for [cid:suffix] combo: %s", cidWithHintAndSuffix)
	}

	suffixDelimiter := strings.LastIndex(cidWithHintAndSuffix, docutil.NamespaceDelimiter)

	adjustedPos := suffixDelimiter + 1
	if adjustedPos >= len(cidWithHintAndSuffix) {
		return "", "", fmt.Errorf("did suffix is empty")
	}

	return cidWithHintAndSuffix[:adjustedPos-1], cidWithHintAndSuffix[adjustedPos:], nil
}

func (cs *Client) getWebFingerURL(anchorOrigin string) (string, error) {
	u, err := url.Parse(anchorOrigin)
	if err != nil {
		return "", fmt.Errorf("parse anchor origin URL [%s]: %w", anchorOrigin, err)
	}

	switch u.Scheme {
	case "http", "https":
		return fmt.Sprintf("%s/.well-known/host-meta.json", fmt.Sprintf("%s://%s", u.Scheme, u.Host)), nil
	case "did":
		domain, err := cs.ResolveDomainForDID(anchorOrigin)
		if err != nil {
			return "", fmt.Errorf("get domain from [%s]", anchorOrigin)
		}

		return fmt.Sprintf("%s/.well-known/host-meta.json", domain), nil
	case "ipns":
		anchorOriginSplit := strings.Split(anchorOrigin, "ipns://")

		return fmt.Sprintf("%s/%s/%s/.well-known/host-meta.json", ipfsGlobal, "ipns",
			anchorOriginSplit[1]), nil
	default:
		return "", fmt.Errorf("anchorOrigin %s not supported", anchorOrigin)
	}
}

func (cs *Client) getLatestAnchorOrigin(anchorOrigin, didURI string) (*restapi.JRD, error) {
	var jrd restapi.JRD

	webFingerURL, err := cs.getWebFingerURL(anchorOrigin)
	if err != nil {
		return nil, err
	}

	err = cs.sendRequest(nil, http.MethodGet, webFingerURL, &jrd)
	if err != nil {
		return nil, err
	}

	templateURL := ""

	for _, v := range jrd.Links {
		if v.Rel == self && v.Type == "application/jrd+json" {
			templateURL = strings.ReplaceAll(v.Template, "{uri}", didURI)

			break
		}
	}

	if templateURL == "" {
		return nil, fmt.Errorf("failed to find template url in webfinger doc")
	}

	err = cs.sendRequest(nil, http.MethodGet, templateURL, &jrd)
	if err != nil {
		return nil, err
	}

	return &jrd, nil
}

func (cs *Client) send(req []byte, method, endpointURL string) ([]byte, error) {
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	}

	httpReq.Header.Set("Content-Type", "application/json")

	authToken := cs.authToken

	if cs.authTokenProvider != nil {
		v, errToken := cs.authTokenProvider.AuthToken()
		if errToken != nil {
			return nil, errToken
		}

		authToken = "Bearer " + v
	}

	if authToken != "" {
		httpReq.Header.Add("Authorization", authToken)
	}

	resp, err := cs.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func (cs *Client) sendRequest(req []byte, method, endpointURL string, respObj interface{}) error { //nolint: unparam
	responseBytes, err := cs.send(req, method, endpointURL)
	if err != nil {
		return err
	}

	return json.Unmarshal(responseBytes, &respObj)
}

func closeResponseBody(respBody io.Closer) {
	if e := respBody.Close(); e != nil {
		log.CloseResponseBodyError(logger, e)
	}
}

type authTokenProvider interface {
	AuthToken() (string, error)
}

// Option is a config service instance option.
type Option func(opts *Client)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient httpClient) Option {
	return func(opts *Client) {
		opts.httpClient = httpClient
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *Client) {
		opts.authToken = "Bearer " + authToken
	}
}

// WithAuthTokenProvider add auth token provider.
func WithAuthTokenProvider(p authTokenProvider) Option {
	return func(opts *Client) {
		opts.authTokenProvider = p
	}
}

// WithDisableProofCheck disable proof check.
func WithDisableProofCheck(disable bool) Option {
	return func(opts *Client) {
		opts.disableProofCheck = disable
	}
}

// WithPublicKeyFetcher sets the public key fetcher. If not set then
// the default fetcher is used.
func WithPublicKeyFetcher(pkf verifiable.PublicKeyFetcher) Option {
	return func(opts *Client) {
		opts.publicKeyFetcher = pkf
	}
}

// WithDIDWebHTTP use did web http.
func WithDIDWebHTTP(enable bool) Option {
	return func(opts *Client) {
		opts.didWebHTTP = enable
	}
}

// WithNamespace option is for custom namespace.
func WithNamespace(namespace string) Option {
	return func(opts *Client) {
		opts.namespace = namespace
	}
}

// WithCacheLifetime option defines the lifetime of an object in the cache.
func WithCacheLifetime(lifetime time.Duration) Option {
	return func(opts *Client) {
		opts.cacheLifetime = lifetime
	}
}

// WithCacheSize option defines the cache size.
func WithCacheSize(size int) Option {
	return func(opts *Client) {
		opts.cacheSize = size
	}
}

// WithVDR option is for custom VDR. If not specified then the default VDR is used.
func WithVDR(r vdrapi.Registry) Option {
	return func(opts *Client) {
		opts.vdr = r
	}
}

type webVDR struct {
	http    httpClient
	useHTTP bool
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if w.useHTTP {
		opts = append(opts, vdrapi.WithOption(web.UseHTTPOpt, true))
	}

	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
}

// This type to be moved/reworked in the future.
type referenceCASReaderImplementation struct {
	// This is here since this implementation uses the send method from the Client.
	// It creates a bit of a weird circular dependency-type of issue (since Client relies on a casReader),
	// so really the send method should be extracted.
	s *Client
}

func (c *referenceCASReaderImplementation) Read(cidWithPossibleHint string) ([]byte, error) {
	cidWithPossibleHintParts := strings.Split(cidWithPossibleHint, ":")
	if len(cidWithPossibleHintParts) > 1 {
		// hint provided
		return c.resolveCIDWithHint(cidWithPossibleHintParts)
	}

	// we only got cid so try IPFS
	return c.s.send(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cidWithPossibleHint))
}

func (c *referenceCASReaderImplementation) resolveCIDWithHint(cidWithPossibleHintParts []string) ([]byte, error) {
	var value []byte

	var err error

	switch cidWithPossibleHintParts[0] {
	case "ipfs":
		value, err = c.s.send(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cidWithPossibleHintParts[1]))
	case "webcas": //nolint: wsl // Intentionally left as documentation
		// TODO: Add support for default webcas reader (without storage)
		// The commented code below shows how this can be achieved.
		// To be enabled in the future (and this type may be moved somewhere else)
		// domain := cidWithPossibleHintParts[1]
		//
		// // If the domain in the hint contains a port, this will ensure it's included.
		// if len(cidWithPossibleHintParts) == 4 {
		//	domain = fmt.Sprintf("%s:%s", domain, cidWithPossibleHintParts[2])
		// }
		//
		// cid := cidWithPossibleHintParts[len(cidWithPossibleHintParts)-1]
		//
		// value, err = c.webCASResolver.Resolve(domain, cid)
		// if err != nil {
		//	return nil, fmt.Errorf("failed to resolve domain and CID via WebCAS: %w", err)
		// }

		return nil, fmt.Errorf("hint 'webcas' will be supported soon")
	default:
		return nil, fmt.Errorf("hint '%s' not supported", cidWithPossibleHintParts[0])
	}

	if err != nil {
		return nil, fmt.Errorf("failed to resolve cidWithHint%s: %w", cidWithPossibleHintParts, err)
	}

	return value, nil
}
