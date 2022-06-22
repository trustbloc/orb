/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"
)

func TestNewPublisherPool(t *testing.T) {
	t.Run("No pool", func(t *testing.T) {
		amqpCfg := newDefaultQueueConfig(Config{URI: mqURI})

		p, err := newPublisherPool(&mockConnectionMgr{}, 9, &amqpCfg,
			func(cfg *amqp.Config, conn connection) (publisher, error) {
				return newMockPublisher(), nil
			},
		)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Len(t, p.publishers, 1)
		require.NoError(t, p.Publish("topic", &message.Message{}))
		require.NoError(t, p.Close())
	})

	t.Run("With pool", func(t *testing.T) {
		amqpCfg := newDefaultQueueConfig(Config{URI: mqURI})
		amqpCfg.Publish.ChannelPoolSize = 50

		p, err := newPublisherPool(&mockConnectionMgr{}, 9, &amqpCfg,
			func(cfg *amqp.Config, conn connection) (publisher, error) {
				return newMockPublisher(), nil
			},
		)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Len(t, p.publishers, 6)
		require.NoError(t, p.Publish("topic", &message.Message{}))
		require.NoError(t, p.Close())
	})

	t.Run("Create connection error", func(t *testing.T) {
		errExpected := errors.New("injected create connection error")

		amqpCfg := newDefaultQueueConfig(Config{URI: mqURI})

		p, err := newPublisherPool(&mockConnectionMgr{err: errExpected}, 9,
			&amqpCfg, func(cfg *amqp.Config, conn connection) (publisher, error) {
				return newMockPublisher(), nil
			},
		)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Create publisher error", func(t *testing.T) {
		errExpected := errors.New("injected create publisher error")

		amqpCfg := newDefaultQueueConfig(Config{URI: mqURI})

		p, err := newPublisherPool(&mockConnectionMgr{}, 9,
			&amqpCfg, func(cfg *amqp.Config, conn connection) (publisher, error) {
				return nil, errExpected
			},
		)
		require.Error(t, err)
		require.Nil(t, p)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Close error", func(t *testing.T) {
		errExpected := errors.New("injected close error")

		amqpCfg := newDefaultQueueConfig(Config{URI: mqURI})
		amqpCfg.Publish.ChannelPoolSize = 50

		p, err := newPublisherPool(&mockConnectionMgr{}, 9, &amqpCfg,
			func(cfg *amqp.Config, conn connection) (publisher, error) {
				return &mockPublisher{mockClosable: &mockClosable{err: errExpected}}, nil
			},
		)
		require.NoError(t, err)
		require.NotNil(t, p)

		err = p.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestRoundRobinRace(t *testing.T) {
	const (
		concurrency = 10
		num         = 100000
		maxIndex    = 99
	)

	lb := newRoundRobin(maxIndex)

	var wg sync.WaitGroup

	for p := 0; p < concurrency; p++ {
		wg.Add(1)

		go func() {
			time.Sleep(100 * time.Millisecond)

			for i := 0; i < num; i++ {
				require.True(t, lb.nextIndex() <= maxIndex)
			}

			wg.Done()
		}()
	}

	wg.Wait()
}
