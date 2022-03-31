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

// Client implements webfinger client.
type Client struct {
	httpClient httpClient

	cacheLifetime time.Duration
	cacheSize     int

	ledgerTypeCache gcache.Cache
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

	client.ledgerTypeCache = gcache.New(client.cacheSize).
		Expiration(client.cacheLifetime).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			lt, err := client.getLedgerType(key.(string))
			if err != nil {
				logger.Debugf("failed to load ledger type for domain '%s' into cache: %s", key.(string), err.Error())

				return nil, err
			}

			logger.Debugf("loaded ledger type for domain '%s' into cache: %s", key.(string), lt)

			return lt, nil
		}).Build()

	return client
}

// GetLedgerType returns ledger type for VCT domain.
func (c *Client) GetLedgerType(domain string) (string, error) {
	ledgerTypeObj, err := c.ledgerTypeCache.Get(domain)
	if err != nil {
		return "", fmt.Errorf("failed to get key[%s] from ledger type cache: %w", domain, err)
	}

	return ledgerTypeObj.(string), nil
}

// GetLedgerType returns ledger type.
func (c *Client) getLedgerType(domain string) (string, error) {
	resource := fmt.Sprintf("%s/vct", domain)

	jrd, err := c.ResolveWebFingerResource(domain, resource)
	if err != nil {
		return "", fmt.Errorf("failed to resolve WebFinger resource[%s]: %w", resource, err)
	}

	ltRaw, ok := jrd.Properties[command.LedgerType]
	if !ok {
		return "", model.ErrResourceNotFound
	}

	lt, ok := ltRaw.(string)
	if !ok {
		return "", fmt.Errorf("ledger type '%T' is not a string for Webfinger resource[%s]", ltRaw, resource)
	}

	return lt, nil
}

// HasSupportedLedgerType returns true if domain supports configured ledger type.
func (c *Client) HasSupportedLedgerType(domain string) (bool, error) {
	// TODO: Do we need to configure supported ledger types.
	supportedLedgerTypes := []string{"vct-v1"}

	lt, err := c.GetLedgerType(domain)
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
	webFingerURL := fmt.Sprintf("%s/.well-known/webfinger?resource=%s", domainWithScheme, resource)

	req, err := http.NewRequest(http.MethodGet, webFingerURL, nil)
	if err != nil {
		return restapi.JRD{},
			fmt.Errorf("failed to create new request for WebFinger URL [%s]: %w", webFingerURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return restapi.JRD{}, orberrors.NewTransientf("failed to get response (URL: %s): %w", webFingerURL, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("failed to close response body after getting WebFinger response: %s", err.Error())
		}
	}()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return restapi.JRD{}, orberrors.NewTransientf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return restapi.JRD{}, model.ErrResourceNotFound
		}

		e := fmt.Errorf("received unexpected status code. URL [%s], "+
			"status code [%d], response body [%s]", webFingerURL, resp.StatusCode, string(respBytes))

		if resp.StatusCode >= http.StatusInternalServerError {
			return restapi.JRD{}, orberrors.NewTransient(e)
		}

		return restapi.JRD{}, e
	}

	webFingerResponse := restapi.JRD{}

	err = json.Unmarshal(respBytes, &webFingerResponse)
	if err != nil {
		return restapi.JRD{}, fmt.Errorf("failed to unmarshal WebFinger response: %w", err)
	}

	return webFingerResponse, nil
}

// GetWebCASURL gets the WebCAS URL for cid from domainWithScheme using WebFinger.
func (c *Client) GetWebCASURL(domainWithScheme, cid string) (*url.URL, error) {
	webFingerResponse, err := c.ResolveWebFingerResource(domainWithScheme,
		fmt.Sprintf("%s/cas/%s", domainWithScheme, cid))
	if err != nil {
		return nil, fmt.Errorf("failed to get WebFinger resource: %w", err)
	}

	var webCASURLFromWebFinger string

	// First try to resolve from self.
	for _, link := range webFingerResponse.Links {
		if link.Rel == "self" {
			webCASURLFromWebFinger = link.Href

			break
		}
	}

	if webCASURLFromWebFinger == "" {
		// Try the alternates.
		for _, link := range webFingerResponse.Links {
			if link.Rel == "alternate" {
				webCASURLFromWebFinger = link.Href

				break
			}
		}
	}

	webCASURL, err := url.Parse(webCASURLFromWebFinger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webcas URL: %w", err)
	}

	return webCASURL, nil
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

func contains(l []string, e string) bool {
	for _, s := range l {
		if s == e {
			return true
		}
	}

	return false
}
