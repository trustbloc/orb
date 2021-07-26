/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cenkalti/backoff"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

var logger = log.New("pubsub")

const (
	defaultMaxConnectRetries          = 25
	defaultMaxConnectInterval         = 5 * time.Second
	defaultMaxConnectElapsedTime      = 3 * time.Minute
	defaultMaxConnectionSubscriptions = 1000
)

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	URI                        string
	MaxConnectRetries          uint64
	MaxConnectionSubscriptions int
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

type subscriberFactory = func() (subscriber, error)

type publisherFactory = func() (publisher, error)

// PubSub implements a publisher/subscriber that connects to an AMQP-compatible message queue.
type PubSub struct {
	*lifecycle.Lifecycle
	Config

	config            amqp.Config
	subscriber        subscriber
	publisher         publisher
	pools             []*pooledSubscriber
	mutex             sync.RWMutex
	subscriberFactory subscriberFactory
	createPublisher   publisherFactory
}

// New returns a new AMQP publisher/subscriber.
func New(cfg Config) *PubSub {
	if cfg.MaxConnectionSubscriptions == 0 {
		cfg.MaxConnectionSubscriptions = defaultMaxConnectionSubscriptions
	}

	p := &PubSub{
		Config: cfg,
		config: amqp.NewDurableQueueConfig(cfg.URI),
	}

	p.Lifecycle = lifecycle.New("amqp",
		lifecycle.WithStart(p.start),
		lifecycle.WithStop(p.stop))

	p.subscriberFactory = p.newSubscriber
	p.createPublisher = p.newPublisher

	// Start the service immediately.
	p.Start()

	return p
}

// Subscribe subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	return p.SubscribeWithOpts(ctx, topic)
}

// SubscribeWithOpts subscribes to a topic using the given options, and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) SubscribeWithOpts(ctx context.Context, topic string,
	opts ...spi.Option) (<-chan *message.Message, error) {
	if p.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	options := &spi.Options{}

	for _, opt := range opts {
		opt(options)
	}

	if options.PoolSize == 0 {
		logger.Debugf("Subscribing to topic [%s]", topic)

		return p.subscriber.Subscribe(ctx, topic)
	}

	logger.Debugf("Creating subscriber pool for topic [%s], Size [%d]", topic, options.PoolSize)

	pool, err := newPooledSubscriber(ctx, options.PoolSize, p.subscriber, topic)
	if err != nil {
		return nil, fmt.Errorf("subscriber pool: %w", err)
	}

	p.mutex.Lock()
	p.pools = append(p.pools, pool)
	p.mutex.Unlock()

	pool.start()

	return pool.msgChan, nil
}

// Publish publishes the given messages to the given topic.
func (p *PubSub) Publish(topic string, messages ...*message.Message) error {
	if p.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	logger.Debugf("Publishing messages to topic [%s]", topic)

	if err := p.publisher.Publish(topic, messages...); err != nil {
		return errors.NewTransient(err)
	}

	return nil
}

// Close stops the publisher/subscriber.
func (p *PubSub) Close() error {
	p.Stop()

	return nil
}

func (p *PubSub) stop() {
	logger.Debugf("Closing publisher...")

	if err := p.publisher.Close(); err != nil {
		logger.Warnf("Error closing publisher: %s", err)
	}

	logger.Debugf("Closing subscriber...")

	if err := p.subscriber.Close(); err != nil {
		logger.Warnf("Error closing subscriber: %s", err)
	}

	logger.Debugf("Closing pools...")

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, s := range p.pools {
		s.stop()
	}
}

func (p *PubSub) start() {
	logger.Infof("Connecting to message queue at %s", p.config.Connection.AmqpURI)

	maxRetries := p.MaxConnectRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxConnectRetries
	}

	err := backoff.RetryNotify(
		func() error {
			return p.connect()
		},
		backoff.WithMaxRetries(newBackOff(), maxRetries),
		func(err error, duration time.Duration) {
			logger.Infof("Error connecting to AMQP service %s after %s: %s",
				p.config.Connection.AmqpURI, duration, err)
		},
	)
	if err != nil {
		panic(fmt.Sprintf("Unable to connect to message queue after %d attempts", maxRetries))
	}

	logger.Warnf("Successfully connected to message queue: %s", p.config.Connection.AmqpURI)
}

func (p *PubSub) connect() error {
	pub, err := p.createPublisher()
	if err != nil {
		return err
	}

	p.subscriber = newSubscriberMgr(p.MaxConnectionSubscriptions, p.subscriberFactory)
	p.publisher = pub

	return nil
}

func (p *PubSub) newSubscriber() (subscriber, error) {
	return amqp.NewSubscriber(p.config, wmlogger.New())
}

func (p *PubSub) newPublisher() (publisher, error) {
	return amqp.NewPublisher(p.config, wmlogger.New())
}

func newBackOff() backoff.BackOff {
	b := &backoff.ExponentialBackOff{
		InitialInterval:     backoff.DefaultInitialInterval,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         defaultMaxConnectInterval,
		MaxElapsedTime:      defaultMaxConnectElapsedTime,
		Clock:               backoff.SystemClock,
	}

	b.Reset()

	return b
}

type subscriberInfo struct {
	subscriber    subscriber
	subscriptions int
}

type subscriberConnectionMgr struct {
	createSubscriber  subscriberFactory
	mutex             sync.RWMutex
	subscribers       []*subscriberInfo
	current           *subscriberInfo
	subscriptionLimit int
}

func newSubscriberMgr(limit int, factory subscriberFactory) *subscriberConnectionMgr {
	return &subscriberConnectionMgr{
		subscriptionLimit: limit,
		createSubscriber:  factory,
	}
}

func (m *subscriberConnectionMgr) Close() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logger.Infof("Closing %d subscriber connections", len(m.subscribers))

	for _, s := range m.subscribers {
		if err := s.subscriber.Close(); err != nil {
			logger.Warnf("Error closing subscriber: %s", err)
		}
	}

	return nil
}

func (m *subscriberConnectionMgr) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	s, err := m.get()
	if err != nil {
		return nil, err
	}

	return s.Subscribe(ctx, topic)
}

func (m *subscriberConnectionMgr) get() (subscriber, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.current == nil || m.current.subscriptions >= m.subscriptionLimit {
		logger.Infof("Creating new subscriber connection.")

		s, err := m.createSubscriber()
		if err != nil {
			return nil, err
		}

		newCurrent := &subscriberInfo{subscriber: s}

		m.subscribers = append(m.subscribers, newCurrent)
		m.current = newCurrent

		logger.Infof("Created new subscriber connection. Total subscriber connections: %d.", len(m.subscribers))
	}

	m.current.subscriptions++

	logger.Debugf("Subscriber connections: %d. Current connection has %d subscriptions.",
		len(m.subscribers), m.current.subscriptions)

	return m.current.subscriber, nil
}
