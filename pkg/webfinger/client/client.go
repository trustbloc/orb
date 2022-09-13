/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/bluele/gcache"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/document/util"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/webfinger/model"
)

var logger = log.New("webfinger-client")

const (
	defaultCacheLifetime = 300 * time.Second // five minutes
	defaultCacheSize     = 100
)

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type didDomainResolver func(did string) (string, error)

// Client implements webfinger client.
type Client struct {
	httpClient httpClient

	cacheLifetime    time.Duration
	cacheSize        int
	getDomainFromDID didDomainResolver

	resourceCache gcache.Cache
}

type cacheKey struct {
	domainWithScheme string
	resource         string
}

// New creates new webfinger client.
func New(opts ...Option) *Client {
	client := &Client{
		httpClient:    &http.Client{},
		cacheLifetime: defaultCacheLifetime,
		cacheSize:     defaultCacheSize,
	}

	for _, opt := range opts {
		opt(client)
	}

	client.resourceCache = gcache.New(client.cacheSize).
		Expiration(client.cacheLifetime).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			k := key.(cacheKey) //nolint:errcheck,forcetypeassert

			r, err := client.resolveResource(k.domainWithScheme, k.resource)
			if err != nil {
				return nil, err
			}

			logger.Debugf("Loaded webfinger resource for domain [%s] and resource [%s] into cache: %+v",
				k.domainWithScheme, k.resource, r)

			return r, nil
		}).Build()

	return client
}

// GetLedgerType returns ledger type for the VCT service.
func (c *Client) GetLedgerType(uri string) (string, error) {
	domain, err := c.resolveDomain(uri)
	if err != nil {
		return "", fmt.Errorf("resolve domain: %w", err)
	}

	jrd, err := c.ResolveWebFingerResource(domain, uri)
	if err != nil {
		return "", fmt.Errorf("failed to resolve WebFinger resource[%s]: %w", uri, err)
	}

	ltRaw, ok := jrd.Properties[command.LedgerType]
	if !ok {
		return "", model.ErrResourceNotFound
	}

	lt, ok := ltRaw.(string)
	if !ok {
		return "", fmt.Errorf("ledger type '%T' is not a string for Webfinger resource[%s]", ltRaw, uri)
	}

	return lt, nil
}

// HasSupportedLedgerType returns true if domain supports configured ledger type.
func (c *Client) HasSupportedLedgerType(uri string) (bool, error) {
	// TODO: Do we need to configure supported ledger types.
	supportedLedgerTypes := []string{"vct-v1"}

	lt, err := c.GetLedgerType(uri)
	if err != nil {
		if errors.Is(err, model.ErrResourceNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("getLedgerType: %w", err)
	}

	return contains(supportedLedgerTypes, lt), nil
}

// ResolveWebFingerResource attempts to resolve the given WebFinger resource from domainWithScheme.
func (c *Client) ResolveWebFingerResource(domainWithScheme, resource string) (restapi.JRD, error) {
	r, err := c.resourceCache.Get(cacheKey{
		domainWithScheme: domainWithScheme,
		resource:         resource,
	})
	if err != nil {
		return restapi.JRD{}, fmt.Errorf("get webfinger resource for domain [%s] and resource [%s]: %w",
			domainWithScheme, resource, err)
	}

	return *r.(*restapi.JRD), nil
}

func (c *Client) resolveResource(domainWithScheme, resource string) (*restapi.JRD, error) {
	webFingerURL := fmt.Sprintf("%s/.well-known/webfinger?resource=%s", domainWithScheme, resource)

	req, err := http.NewRequest(http.MethodGet, webFingerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request for WebFinger URL [%s]: %w",
			webFingerURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to get response (URL: %s): %w", webFingerURL, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("failed to close response body after getting WebFinger response: %s", err.Error())
		}
	}()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, model.ErrResourceNotFound
		}

		e := fmt.Errorf("received unexpected status code. URL [%s], "+
			"status code [%d], response body [%s]", webFingerURL, resp.StatusCode, string(respBytes))

		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, orberrors.NewTransient(e)
		}

		return nil, e
	}

	webFingerResponse := &restapi.JRD{}

	err = json.Unmarshal(respBytes, webFingerResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal WebFinger response: %w", err)
	}

	return webFingerResponse, nil
}

func (c *Client) resolveDomain(uri string) (string, error) {
	if util.IsDID(uri) {
		var err error

		domain, err := c.getDomainFromDID(uri)
		if err != nil {
			return "", fmt.Errorf("get domain from did [%s]: %w", uri, err)
		}

		return domain, nil
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("parse URI [%s]: %w", uri, err)
	}

	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

// ResolveLog returns VCT log for the given service URI.
func (c *Client) ResolveLog(uri string) (*url.URL, error) {
	domain, err := c.resolveDomain(uri)
	if err != nil {
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	jrd, err := c.ResolveWebFingerResource(domain, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve WebFinger resource[%s]: %w", domain, err)
	}

	logger.Debugf("jrd response for domain[%s]: %+v", domain, jrd)

	var logURL string

	for _, link := range jrd.Links {
		if link.Rel == "vct" {
			logURL = link.Href

			break
		}
	}

	if logURL == "" {
		return nil, orberrors.ErrContentNotFound
	}

	parsedURL, err := url.Parse(logURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log URL: %w", err)
	}

	return parsedURL, nil
}

// GetWebCASURL gets the WebCAS URL for cid from domainWithScheme using WebFinger.
func (c *Client) GetWebCASURL(domainWithScheme, cid string) (*url.URL, error) {
	return c.resolveLink(domainWithScheme, fmt.Sprintf("%s/cas/%s", domainWithScheme, cid))
}

func (c *Client) resolveLink(domainWithScheme, resource string) (*url.URL, error) {
	response, err := c.ResolveWebFingerResource(domainWithScheme, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to get WebFinger resource: %w", err)
	}

	var u string

	// First try to resolve from self.
	for _, link := range response.Links {
		if link.Rel == "self" {
			u = link.Href

			break
		}
	}

	if u == "" {
		// Try the alternates.
		for _, link := range response.Links {
			if link.Rel == "alternate" {
				u = link.Href

				break
			}
		}
	}

	uri, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return uri, nil
}

// Option is a webfinger client instance option.
type Option func(opts *Client)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient httpClient) Option {
	return func(opts *Client) {
		opts.httpClient = httpClient
	}
}

// WithCacheLifetime option defines the lifetime of an object in the cache.
// If we end-up with multiple caches that require different lifetime
// we may have to add different cache lifetime options.
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

// WithDIDDomainResolver option sets the domain resolver.
func WithDIDDomainResolver(resolver didDomainResolver) Option {
	return func(opts *Client) {
		opts.getDomainFromDID = resolver
	}
}

func contains(l []string, e string) bool {
	for _, s := range l {
		if s == e {
			return true
		}
	}

	return false
}
