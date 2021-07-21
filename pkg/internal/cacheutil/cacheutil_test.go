/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cacheutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/bluele/gcache"
	"github.com/stretchr/testify/require"
)

const value = "value"

func TestCacheUtil(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := newResolver()

		val, err := r.Resolve("key")
		require.NoError(t, err)
		require.Equal(t, value, val)
	})

	t.Run("success - cache expired", func(t *testing.T) {
		r := newResolver()
		r.CacheLifetime = 1 * time.Second

		val, err := r.Resolve("key")
		require.NoError(t, err)
		require.Equal(t, value, val)

		// cache expires
		time.Sleep(2 * time.Second)

		val, err = r.Resolve("key")
		require.NoError(t, err)
		require.Equal(t, value, val)
	})

	t.Run("error - fetcher error", func(t *testing.T) {
		r := newResolver()
		r.ResolveErr = fmt.Errorf("resolve error")

		val, err := r.Resolve("key")
		require.Error(t, err)
		require.Empty(t, val)
		require.Contains(t, err.Error(), "fetching cacheable object: resolve error")
	})

	t.Run("error - cacheable error", func(t *testing.T) {
		r := newResolver()
		r.ResolveObj = &cacheObjType{Err: fmt.Errorf("cacheable error")}

		val, err := r.Resolve("key")
		require.Error(t, err)
		require.Empty(t, val)
		require.Contains(t, err.Error(),
			"failed to get object expiry time: cacheable error")
	})
}

func newResolver() *resolver {
	r := resolver{CacheLifetime: 5 * time.Second}

	r.ResolverCache = MakeCache(
		GetNewCacheable(func(key string) (Cacheable, error) {
			return r.resolve(key)
		}))

	return &r
}

type resolver struct {
	CacheLifetime time.Duration
	ResolverCache gcache.Cache

	ResolveErr error
	ResolveObj *cacheObjType
}

func (r *resolver) Resolve(key string) (string, error) {
	cachedObj, err := r.ResolverCache.Get(key)
	if err != nil {
		return "", err
	}

	obj, ok := cachedObj.(*cacheObjType)
	if !ok {
		return "", fmt.Errorf("unexpected interface for cached object")
	}

	return obj.Value, nil
}

func (r *resolver) resolve(_ string) (*cacheObjType, error) {
	if r.ResolveErr != nil {
		return nil, r.ResolveErr
	}

	if r.ResolveObj != nil {
		return r.ResolveObj, nil
	}

	return &cacheObjType{Value: "value", MaxAge: r.CacheLifetime}, nil
}

type cacheObjType struct {
	Value  string
	MaxAge time.Duration
	Err    error
}

// CacheLifetime returns the cache object lifetime before it needs to be checked for an update.
func (t *cacheObjType) CacheLifetime() (time.Duration, error) {
	if t.Err != nil {
		return 0, t.Err
	}

	return t.MaxAge, nil
}
