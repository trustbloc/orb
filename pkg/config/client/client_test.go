/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const configStoreName = "orb-config"

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore)
		require.NoError(t, err)
		require.NotNil(t, configClient)

		require.Equal(t, defaultCacheExpiration, configClient.cacheExpiry)
		require.Equal(t, defaultCacheSize, configClient.cacheSize)
	})

	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		cacheExpiry := time.Hour
		cacheSize := 1000

		configClient := New(configStore, WithCacheLifetime(cacheExpiry), WithCacheSize(cacheSize))
		require.NoError(t, err)
		require.NotNil(t, configClient)

		require.Equal(t, cacheExpiry, configClient.cacheExpiry)
		require.Equal(t, cacheSize, configClient.cacheSize)
	})
}

func TestGetValue(t *testing.T) {
	const key = "key"

	const value = "value"

	t.Run("success - call to cache loader function", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore, WithCacheLifetime(1*time.Second))
		require.NoError(t, err)
		require.NotNil(t, configClient)

		err = configStore.Put(key, []byte(value))
		require.NoError(t, err)

		// calls cache loader function
		val, err := configClient.GetValue(key)
		require.NoError(t, err)
		require.Equal(t, value, string(val))

		val, err = configClient.GetValue(key)
		require.NoError(t, err)
		require.Equal(t, value, string(val))

		time.Sleep(2 * time.Second)

		// calls cache loader function again
		val, err = configClient.GetValue(key)
		require.NoError(t, err)
		require.Equal(t, value, string(val))
	})

	t.Run("error - config store error", func(t *testing.T) {
		configStore := &storemocks.Store{}
		configStore.GetReturns(nil, fmt.Errorf("get error"))

		configClient := New(configStore)

		val, err := configClient.GetValue(key)
		require.Error(t, err)
		require.Nil(t, val)
		require.Contains(t, err.Error(), "get error")
	})
}

func TestGetEndpoint(t *testing.T) {
	const logURLValue = "https://vct.com/log"

	const empty = ""

	t.Run("success - retrieve from cache and from store", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore)
		require.NoError(t, err)
		require.NotNil(t, configClient)

		logURLValueBytes, err := json.Marshal(&logCfg{URL: logURLValue})
		require.NoError(t, err)

		err = configStore.Put(logURL, logURLValueBytes)
		require.NoError(t, err)

		// calls cache loader function
		endpoint, err := configClient.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, logURLValue, endpoint)

		// gets value from cache
		endpoint, err = configClient.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, logURLValue, endpoint)
	})

	t.Run("success - empty log URL", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore)
		require.NoError(t, err)
		require.NotNil(t, configClient)

		logURLValueBytes, err := json.Marshal(&logCfg{URL: ""})
		require.NoError(t, err)

		err = configStore.Put(logURL, logURLValueBytes)
		require.NoError(t, err)

		// calls cache loader function
		endpoint, err := configClient.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, empty, endpoint)

		// gets value from cache
		endpoint, err = configClient.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, empty, endpoint)
	})

	t.Run("error - log URL not configured", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore)
		require.NoError(t, err)
		require.NotNil(t, configClient)

		// calls cache loader function
		endpoint, err := configClient.GetLogEndpoint()
		require.Error(t, err)
		require.Empty(t, endpoint)
		require.Contains(t, err.Error(), "failed to retrieve log endpoint from config cache: "+
			"failed to retrieve key 'log-url' from config cache: data not found")
	})

	t.Run("error - unmarshal log URL ", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		configClient := New(configStore)
		require.NoError(t, err)
		require.NotNil(t, configClient)

		err = configStore.Put(logURL, []byte(logURLValue))
		require.NoError(t, err)

		// calls cache loader function
		endpoint, err := configClient.GetLogEndpoint()
		require.Error(t, err)
		require.Equal(t, empty, endpoint)
		require.Contains(t, err.Error(), "failed to unmarshal log config")
	})
}
