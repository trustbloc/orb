/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cenkalti/backoff"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

var logger = log.New("pubsub")

const defaultMaxConnectRetries = 15

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	URI               string
	MaxConnectRetries uint64
}

type closeable interface {
	Close() error
}

type subscriber interface {
	closeable
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

type publisher interface {
	closeable
	Publish(topic string, messages ...*message.Message) error
}

// PubSub implements a publisher/subscriber that connects to an AMQP-compatible message queue.
type PubSub struct {
	*lifecycle.Lifecycle
	Config

	serviceName string
	config      amqp.Config
	subscriber  subscriber
	publisher   publisher
}

// New returns a new AMQP publisher/subscriber.
func New(name string, cfg Config) *PubSub {
	p := &PubSub{
		Config:      cfg,
		serviceName: name,
		config:      amqp.NewDurableQueueConfig(cfg.URI),
	}

	p.Lifecycle = lifecycle.New("amqp-"+name, lifecycle.WithStart(p.start))

	// Start the service immediately.
	p.Start()

	return p
}

// Subscribe subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	if p.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	logger.Debugf("[%s] Subscribing to topic [%s]", p.serviceName, topic)

	return p.subscriber.Subscribe(ctx, topic)
}

// Publish publishes the given messages to the given topic.
func (p *PubSub) Publish(topic string, messages ...*message.Message) error {
	if p.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	logger.Debugf("[%s] Publishing messages to topic [%s]", p.serviceName, topic)

	return p.publisher.Publish(topic, messages...)
}

// Close stops the publisher/subscriber.
func (p *PubSub) Close() error {
	p.Stop()

	logger.Debugf("[%s] Closing publisher...", p.serviceName)

	if err := p.publisher.Close(); err != nil {
		logger.Warnf("[%s] Error closing publisher: %s", err)
	}

	logger.Debugf("[%s] Closing subscriber...", p.serviceName)

	if err := p.subscriber.Close(); err != nil {
		logger.Warnf("[%s] Error closing subscriber: %s", err)
	}

	return nil
}

func (p *PubSub) start() {
	logger.Infof("[%s] Connecting to message queue at %s", p.serviceName, p.config.Connection.AmqpURI)

	maxRetries := p.MaxConnectRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxConnectRetries
	}

	err := backoff.RetryNotify(
		func() error {
			return p.connect()
		},
		backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries),
		func(err error, duration time.Duration) {
			logger.Infof("[%s] Error connecting to AMQP service %s after %s: %s",
				p.serviceName, p.config.Connection.AmqpURI, duration, err)
		},
	)
	if err != nil {
		panic(fmt.Sprintf("[%s] Unable to connect to message queue after %d attempts", p.serviceName, maxRetries))
	}

	logger.Warnf("[%s] Successfully connected to message queue: %s", p.serviceName, p.config.Connection.AmqpURI)
}

func (p *PubSub) connect() error {
	subscriber, err := amqp.NewSubscriber(p.config, wmlogger.New())
	if err != nil {
		return err
	}

	publisher, err := amqp.NewPublisher(p.config, wmlogger.New())
	if err != nil {
		return err
	}

	p.subscriber = subscriber
	p.publisher = publisher

	return nil
}
