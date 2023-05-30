/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import (
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache_Get(t *testing.T) {
	const (
		key    = "key1"
		value1 = "value1"
		value2 = "value2"
	)

	t.Run("No background refresh", func(t *testing.T) {
		i := 0

		c := New(
			func(key interface{}) (interface{}, error) {
				if i == 1 {
					return value2, nil
				}

				i++

				return value1, nil
			},
			WithName("test-cache"),
		)

		v, err := c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value1, v)

		time.Sleep(100 * time.Millisecond)

		v, err = c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value1, v)
	})

	t.Run("Background refresh", func(t *testing.T) {
		i := 0

		c := New(
			func(key interface{}) (interface{}, error) {
				if i >= 1 {
					return value2, nil
				}

				i++

				return value1, nil
			},
			WithName("test-cache"),
			WithMonitorInterval(50*time.Millisecond),
			WithRefreshInterval(100*time.Millisecond),
		)

		c.Start()

		v, err := c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value1, v)

		time.Sleep(200 * time.Millisecond)

		v, err = c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value2, v)

		c.Stop()
	})

	t.Run("Background refresh - success after retry", func(t *testing.T) {
		errExpected := errors.New("injected load error")

		i := 0

		c := New(
			func(key interface{}) (interface{}, error) {
				if i == 0 {
					i++

					t.Logf("Loading... - Returning: %s", value1)

					return value1, nil
				}

				if i == 1 {
					i++

					t.Logf("Loading... - Returning error: %s", errExpected)

					return nil, errExpected
				}

				t.Logf("Loading... - Returning: %s", value2)

				return value2, nil
			},
			WithName("test-cache"),
			WithMonitorInterval(10*time.Millisecond),
			WithRefreshInterval(25*time.Millisecond),
			WithRetryBackoff(50*time.Millisecond),
			WithMaxLoadAttempts(5),
		)

		c.Start()

		v, err := c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value1, v)

		time.Sleep(30 * time.Millisecond)

		v, err = c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value1, v)

		time.Sleep(100 * time.Millisecond)

		v, err = c.Get(key)
		require.NoError(t, err)
		require.Equal(t, value2, v)

		c.Stop()
	})

	t.Run("Background refresh - max failed attempts", func(t *testing.T) {
		errExpected := errors.New("injected load error")

		c := New(
			func(key interface{}) (interface{}, error) {
				t.Logf("Loading... - Returning error: %s", errExpected)

				return nil, errExpected
			},
			WithName("test-cache"),
			WithMonitorInterval(10*time.Millisecond),
			WithRefreshInterval(20*time.Millisecond),
			WithRetryBackoff(30*time.Millisecond),
			WithMaxLoadAttempts(5),
		)

		c.Start()

		v, err := c.Get(key)
		require.EqualError(t, err, err.Error())
		require.Nil(t, v)

		time.Sleep(time.Second)

		v, err = c.Get(key)
		require.EqualError(t, err, err.Error())
		require.Nil(t, v)

		c.Stop()
	})
}

func TestCache_Concurrency(t *testing.T) {
	var numCalls atomic.Int32

	c := New(
		func(key interface{}) (interface{}, error) {
			numCalls.Add(1)

			return fmt.Sprintf("Value for %s", key), nil
		},
		WithName("concurrency-test-cache"),
		WithMonitorInterval(5*time.Millisecond),
		WithRefreshInterval(10*time.Millisecond))

	c.Start()

	const numItems = 100

	go func() {
		for {
			c.MarkAsStale(fmt.Sprintf("id_%d", rand.Intn(numItems)))

			time.Sleep(100 * time.Millisecond)
		}
	}()

	go func() {
		for {
			value, err := c.Get(fmt.Sprintf("id_%d", rand.Intn(numItems)))
			require.NoError(t, err)
			require.NotNil(t, value)

			time.Sleep(20 * time.Millisecond)
		}
	}()

	time.Sleep(3 * time.Second)

	c.Stop()

	t.Logf("Called loader %d times", numCalls.Load())
}
