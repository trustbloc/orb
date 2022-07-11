/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("config-client")

const (
	defaultCacheSize       = 100
	defaultCacheExpiration = 5 * time.Second
)

// Client implements retrieving and caching of config store parameters.
type Client struct {
	configStore storage.Store

	configCache gcache.Cache
	cacheExpiry time.Duration
	cacheSize   int

	unmarshal func([]byte, interface{}) error
}

// New returns a new config store client.
func New(cfg storage.Store, opts ...Option) *Client {
	client := &Client{
		configStore: cfg,

		cacheExpiry: defaultCacheExpiration,
		cacheSize:   defaultCacheSize,

		unmarshal: json.Unmarshal,
	}

	for _, opt := range opts {
		opt(client)
	}

	logger.Debugf("creating config store cache with size=%d, expiration=%s", client.cacheSize, client.cacheExpiry)

	client.configCache = gcache.New(client.cacheSize).ARC().
		Expiration(client.cacheExpiry).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			return client.get(key.(string))
		}).Build()

	return client
}

// Option is a config client instance option.
type Option func(opts *Client)

// WithCacheLifetime option defines the lifetime of an object in the cache.
func WithCacheLifetime(expiry time.Duration) Option {
	return func(opts *Client) {
		opts.cacheExpiry = expiry
	}
}

// WithCacheSize option defines the cache size.
func WithCacheSize(size int) Option {
	return func(opts *Client) {
		opts.cacheSize = size
	}
}

func (c *Client) get(key string) ([]byte, error) {
	val, err := c.configStore.Get(key)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, orberrors.NewTransientf("get config for key [%s]: %w", key, err)
	}

	logger.Debugf("loaded key from config store: %s", key)

	return val, nil
}

// GetValue returns value from config store for specified key.
func (c *Client) GetValue(key string) ([]byte, error) {
	value, err := c.configCache.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key '%s' from config cache: %w", key, err)
	}

	valueBytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected interface '%T' for '%s' value in config cache", value, key)
	}

	return valueBytes, nil
}
