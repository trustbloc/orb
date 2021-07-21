/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cacheutil

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
)

// Cacheable interface has to implemented by objects in the cache.
type Cacheable interface {
	CacheLifetime() (time.Duration, error)
}

// GetNewCacheable uses fetcher function to retrieve object.
func GetNewCacheable(
	fetcher func(key string) (Cacheable, error),
) func(key string) (interface{}, *time.Duration, error) {
	return func(key string) (interface{}, *time.Duration, error) {
		data, err := fetcher(key)
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

// MakeCache is helper function to create cache with string keys.
func MakeCache(fetcher func(key string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		r, ok := key.(string)
		if !ok {
			return nil, nil, fmt.Errorf("key must be string")
		}

		return fetcher(r)
	}).Build()
}
