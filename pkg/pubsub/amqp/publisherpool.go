/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"fmt"
	"sync/atomic"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
)

type publishFunc func(topic string, messages ...*message.Message) error

type createPublisherFunc func(cfg *amqp.Config, conn connection) (publisher, error)

type publisherPool struct {
	publishers []publisher
	publish    publishFunc
}

func newPublisherPool(connMgr connMgr, maxChannelsPerConn int, cfg *amqp.Config,
	createPublisher createPublisherFunc) (*publisherPool, error) {
	publishers, err := createPublishers(connMgr, maxChannelsPerConn, cfg, createPublisher)
	if err != nil {
		return nil, fmt.Errorf("create publishers: %w", err)
	}

	var publish publishFunc

	if len(publishers) == 1 {
		publish = publishers[0].Publish
	} else {
		lb := newRoundRobin(len(publishers) - 1)

		publish = func(topic string, messages ...*message.Message) error {
			i := lb.nextIndex()

			logger.Debugf("Using publisher at index %d", i)

			return publishers[i].Publish(topic, messages...)
		}
	}

	return &publisherPool{
		publishers: publishers,
		publish:    publish,
	}, nil
}

func (p *publisherPool) Publish(topic string, messages ...*message.Message) error {
	return p.publish(topic, messages...)
}

func (p *publisherPool) Close() error {
	logger.Debugf("Closing publisher pool.")

	var lastErr error

	for _, p := range p.publishers {
		if err := p.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func createPublishers(connMgr connMgr, maxChannelsPerConn int, cfg *amqp.Config,
	createPublisher createPublisherFunc) ([]publisher, error) {
	var numPublishers int

	if cfg.Publish.ChannelPoolSize == 0 {
		numPublishers = 1
	} else {
		numPublishers = cfg.Publish.ChannelPoolSize / maxChannelsPerConn

		if cfg.Publish.ChannelPoolSize%maxChannelsPerConn > 0 {
			numPublishers++
		}
	}

	newCfg := *cfg

	// Split the channels evenly across the connections.
	newCfg.Publish.ChannelPoolSize /= numPublishers

	var publishers []publisher

	for i := 0; i < numPublishers; i++ {
		conn, err := connMgr.getConnection(false)
		if err != nil {
			return nil, fmt.Errorf("get connection: %w", err)
		}

		pub, err := createPublisher(&newCfg, conn)
		if err != nil {
			return nil, fmt.Errorf("new publisher: %w", err)
		}

		publishers = append(publishers, pub)
	}

	logger.Infof("Created %d publisher connections at [%s], each with a channel pool size of %d",
		len(publishers), extractEndpoint(newCfg.Connection.AmqpURI), newCfg.Publish.ChannelPoolSize)

	return publishers, nil
}

type roundRobin struct {
	max     int
	current int32
}

func newRoundRobin(max int) *roundRobin {
	return &roundRobin{max: max}
}

func (r *roundRobin) nextIndex() int {
	var i int32

	for {
		i = atomic.AddInt32(&r.current, 1)

		if int(i) > r.max {
			if !atomic.CompareAndSwapInt32(&r.current, i, 0) {
				continue
			}

			i = 0
		}

		return int(i)
	}
}
