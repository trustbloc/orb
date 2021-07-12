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
	"time"

	"github.com/bluele/gcache"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/webfinger/model"
)

var logger = log.New("webfinger-client")

const defaultCacheLifetime = 300 * time.Second // five minutes

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

// Client implements webfinger client.
type Client struct {
	httpClient    httpClient
	cacheLifetime time.Duration

	ledgerTypeCache gcache.Cache
}

// New creates new webfinger client.
func New(opts ...Option) *Client {
	client := &Client{httpClient: &http.Client{}, cacheLifetime: defaultCacheLifetime}

	for _, opt := range opts {
		opt(client)
	}

	client.ledgerTypeCache = makeCache(
		client.getNewCacheable(func(domain string) (cacheable, error) {
			return client.getLedgerType(domain)
		}))

	return client
}

// GetLedgerType returns ledger type for domain.
func (c *Client) GetLedgerType(domain string) (string, error) {
	ledgerType, err := getEntryHelper(c.ledgerTypeCache, domain, "ledgerType")
	if err != nil {
		return "", err
	}

	return ledgerType.(*model.LedgerType).Value, nil
}

// GetLedgerType returns ledger type for domain.
func (c *Client) getLedgerType(domain string) (*model.LedgerType, error) {
	webfingerURL := fmt.Sprintf("%s/.well-known/webfinger?resource=%s/vct", domain, domain)

	logger.Debugf("retrieving ledger type from webfingerURL: %s", webfingerURL)

	req, err := http.NewRequest(http.MethodGet, webfingerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to created new request for webfingerURL[%s]: %w", webfingerURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to webfingerURL[%s]: %w", webfingerURL, err)
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			logger.Warnf("failed to close response body from %s: %s", webfingerURL, e)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, model.ErrLedgerTypeNotFound
	}

	if resp.StatusCode != http.StatusOK {
		responseBody, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			logger.Warnf("failed to read response body for webfingerURI[%s]: %w", webfingerURL, readErr)
		}

		return nil, fmt.Errorf("failed to retrieve data from webfingerURL[%s]"+
			" status code: %d message: %s", webfingerURL, resp.StatusCode, string(responseBody))
	}

	var jrd *restapi.JRD

	if err = json.NewDecoder(resp.Body).Decode(&jrd); err != nil {
		return nil, fmt.Errorf("decode JRD: %w", err)
	}

	ltRaw, ok := jrd.Properties[command.LedgerType]
	if !ok {
		return nil, model.ErrLedgerTypeNotFound
	}

	lt, ok := ltRaw.(string)
	if !ok {
		return nil, fmt.Errorf("ledger type '%T' is not a string", ltRaw)
	}

	return &model.LedgerType{Value: lt, MaxAge: c.cacheLifetime}, nil
}

// HasSupportedLedgerType returns true if domain supports configured ledger type.
func (c *Client) HasSupportedLedgerType(domain string) (bool, error) {
	// TODO: Do we need to configure supported ledger types.
	supportedLedgerTypes := []string{"vct-v1"}

	lt, err := c.GetLedgerType(domain)
	if err != nil {
		if errors.Is(err, model.ErrLedgerTypeNotFound) {
			return false, nil
		}

		return false, err
	}

	return contains(supportedLedgerTypes, lt), nil
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

func getEntryHelper(cache gcache.Cache, key interface{}, objectName string) (interface{}, error) {
	data, err := cache.Get(key)
	if err != nil {
		return nil, fmt.Errorf("getting %s from cache: %w", objectName, err)
	}

	logger.Debugf("got value for key[%v] from cache: %+v", key, data)

	return data, nil
}

func (c *Client) getNewCacheable(
	fetcher func(domain string) (cacheable, error),
) func(domain string) (interface{}, *time.Duration, error) {
	return func(domain string) (interface{}, *time.Duration, error) {
		data, err := fetcher(domain)
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

func makeCache(fetcher func(key string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		r, ok := key.(string)
		if !ok {
			return nil, nil, fmt.Errorf("key must be string")
		}

		return fetcher(r)
	}).Build()
}

func contains(l []string, e string) bool {
	for _, s := range l {
		if s == e {
			return true
		}
	}

	return false
}
