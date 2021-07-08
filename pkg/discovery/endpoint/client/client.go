/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package client implements endpoint client
//
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/orbclient"
)

var logger = log.New("endpoint-client")

const (
	minResolvers         = "https://trustbloc.dev/ns/min-resolvers"
	anchorOriginProperty = "https://trustbloc.dev/ns/anchor-origin"

	namespace  = "did:orb"
	ipfsGlobal = "https://ipfs.io"
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
	namespace                  string
	endpointsCache             gcache.Cache
	endpointsAnchorOriginCache gcache.Cache
	httpClient                 httpClient
	casReader                  casReader
	authToken                  string
	disableProofCheck          bool
	docLoader                  ld.DocumentLoader
	orbClient                  orbClient
}

type req struct {
	did, domain string
}

// New create new endpoint client.
func New(docLoader ld.DocumentLoader, opts ...Option) (*Client, error) {
	configService := &Client{namespace: namespace, docLoader: docLoader, httpClient: &http.Client{}}

	// default to global ipfs reader
	configService.casReader = &defaultCASReader{s: configService}

	for _, opt := range opts {
		opt(configService)
	}

	var orbClientOpts []orbclient.Option

	orbClientOpts = append(orbClientOpts, orbclient.WithJSONLDDocumentLoader(docLoader))

	if configService.disableProofCheck {
		orbClientOpts = append(orbClientOpts, orbclient.WithDisableProofCheck(configService.disableProofCheck))
	} else {
		orbClientOpts = append(orbClientOpts, orbclient.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(vdr.New(vdr.WithVDR(&webVDR{
				http: configService.httpClient,
				VDR:  web.New(),
			}),
			)).PublicKeyFetcher()))
	}

	orbClient, err := orbclient.New(configService.namespace, configService.casReader, orbClientOpts...)
	if err != nil {
		return nil, err
	}

	configService.orbClient = orbClient

	configService.endpointsCache = makeCache(
		configService.getNewCacheable(func(did, domain string) (cacheable, error) {
			return configService.getEndpoint(domain)
		}))

	configService.endpointsAnchorOriginCache = makeCache(
		configService.getNewCacheable(func(did, domain string) (cacheable, error) {
			return configService.getEndpointAnchorOrigin(did)
		}))

	return configService, nil
}

func makeCache(fetcher func(did, domain string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		r, ok := key.(req)
		if !ok {
			return nil, nil, fmt.Errorf("key must be stringPair")
		}

		return fetcher(r.did, r.domain)
	}).Build()
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

func (cs *Client) getNewCacheable(
	fetcher func(did, domain string) (cacheable, error),
) func(did, domain string) (interface{}, *time.Duration, error) {
	return func(did, domain string) (interface{}, *time.Duration, error) {
		data, err := fetcher(did, domain)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching cacheable object: %w", err)
		}

		expiryTime, err := data.CacheLifetime()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get object expiry time: %w", err)
		}

		return data, &expiryTime, nil
	}
}

func getEntryHelper(cache gcache.Cache, key interface{}, objectName string) (interface{}, error) {
	data, err := cache.Get(key)
	if err != nil {
		return nil, fmt.Errorf("getting %s from cache: %w", objectName, err)
	}

	return data, nil
}

// GetEndpoint fetches endpoints from domain, caching the value.
func (cs *Client) GetEndpoint(domain string) (*models.Endpoint, error) {
	endpoint, err := getEntryHelper(cs.endpointsCache, req{
		domain: domain,
	}, "endpoint")
	if err != nil {
		return nil, err
	}

	return endpoint.(*models.Endpoint), nil
}

// GetEndpointFromAnchorOrigin fetches endpoints from anchor origin, caching the value.
func (cs *Client) GetEndpointFromAnchorOrigin(didURI string) (*models.Endpoint, error) {
	endpoint, err := getEntryHelper(cs.endpointsAnchorOriginCache, req{
		did: didURI,
	}, "endpointAnchorOrigin")
	if err != nil {
		return nil, err
	}

	return endpoint.(*models.Endpoint), nil
}

func (cs *Client) getEndpoint(domain string) (*models.Endpoint, error) {
	var wellKnownResponse restapi.WellKnownResponse

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

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

	return endpoint, nil
}

func (cs *Client) populateAnchorResolutionEndpoint(
	jrd *restapi.JRD) (*models.Endpoint, error) {
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

//nolint: funlen,gocyclo,cyclop
func (cs *Client) populateResolutionEndpoint(webFingerURL string) (*models.Endpoint, error) {
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
		if v.Rel != "self" { //nolint: nestif
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
				logger.Warnf("%s has different policy for n %s", v.Href, minResolvers)

				continue
			}

			if len(webFingerResp.Links) != len(jrd.Links) {
				logger.Warnf("%s has different link", v.Href, minResolvers)

				continue
			}

			for _, link := range webFingerResp.Links {
				if _, ok = m[link.Href]; !ok {
					logger.Warnf("%s has different link", v.Href, minResolvers)

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
		return nil, err
	}

	result, err := cs.orbClient.GetAnchorOrigin(cid, suffix)
	if err != nil {
		return nil, err
	}

	anchorOrigin, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("get anchor origin didn't return string")
	}

	currentAnchorOrigin := anchorOrigin

	var currentWebFingerRespone *restapi.JRD

	for {
		jrdLatestAnchorOrigin, errGet := cs.getLatestAnchorOrigin(currentAnchorOrigin, didURI)
		if errGet != nil {
			return nil, errGet
		}

		latestAnchorOrigin, ok := jrdLatestAnchorOrigin.Properties[anchorOriginProperty].(string)
		if !ok {
			return nil, fmt.Errorf("%s property is not string", anchorOriginProperty)
		}

		if latestAnchorOrigin == currentAnchorOrigin {
			currentWebFingerRespone = jrdLatestAnchorOrigin

			break
		}

		currentAnchorOrigin = latestAnchorOrigin
	}

	return cs.populateAnchorResolutionEndpoint(currentWebFingerRespone)
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
	if strings.HasPrefix(anchorOrigin, "ipns://") {
		anchorOriginSplit := strings.Split(anchorOrigin, "ipns://")

		return fmt.Sprintf("%s/%s/%s/.well-known/host-meta.json", ipfsGlobal, "ipns",
			anchorOriginSplit[1]), nil
	} else if strings.HasPrefix(anchorOrigin, "http://") || strings.HasPrefix(anchorOrigin, "https://") {
		parsedURL, err := url.Parse(anchorOrigin)
		if err != nil {
			return "", err
		}

		urlValue := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

		return fmt.Sprintf("%s/.well-known/host-meta.json", urlValue), nil
	}

	return "", fmt.Errorf("anchorOrigin %s not supported", anchorOrigin)
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
		if v.Rel == "self" && v.Type == "application/jrd+json" {
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
			method, endpointURL, nil)
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

	resp, err := cs.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
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
	e := respBody.Close() // nolint: ifshort
	if e != nil {
		logger.Warnf("Failed to close response body: %v", e)
	}
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

// WithDisableProofCheck disable proof check.
func WithDisableProofCheck(disable bool) Option {
	return func(opts *Client) {
		opts.disableProofCheck = disable
	}
}

// WithCASReader option is for custom CAS reader.
func WithCASReader(casReader casReader) Option {
	return func(opts *Client) {
		opts.casReader = casReader
	}
}

// WithNamespace option is for custom namespace.
func WithNamespace(namespace string) Option {
	return func(opts *Client) {
		opts.namespace = namespace
	}
}

type webVDR struct {
	http httpClient
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
}

type defaultCASReader struct {
	s *Client
}

func (c *defaultCASReader) Read(cidWithPossibleHint string) ([]byte, error) {
	cidWithPossibleHintParts := strings.Split(cidWithPossibleHint, ":")
	if len(cidWithPossibleHintParts) > 1 {
		// hint provided
		return c.resolveCIDWithHint(cidWithPossibleHintParts)
	}

	// we only got cid so try IPFS
	return c.s.send(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cidWithPossibleHint))
}

func (c *defaultCASReader) resolveCIDWithHint(cidWithPossibleHintParts []string) ([]byte, error) {
	var value []byte

	var err error

	switch cidWithPossibleHintParts[0] {
	case "ipfs":
		value, err = c.s.send(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cidWithPossibleHintParts[1]))
	case "webcas":
		// TODO: Add support for default webcas reader (without storage)
		return nil, fmt.Errorf("hint 'webcas' will be supported soon")
	default:
		return nil, fmt.Errorf("hint '%s' not supported", cidWithPossibleHintParts[0])
	}

	if err != nil {
		return nil, fmt.Errorf("failed to resolve cidWithHint%s: %w", cidWithPossibleHintParts, err)
	}

	return value, nil
}
