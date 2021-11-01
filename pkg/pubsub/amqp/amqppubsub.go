/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cenkalti/backoff"
	samqp "github.com/streadway/amqp"
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

	defaultMaxRedeliveryAttempts     = 10
	defaultRedeliveryMultiplier      = 1.5
	defaultRedeliveryInitialInterval = 2 * time.Second
	defaultMaxRedeliveryInterval     = 30 * time.Second

	exchange           = "orb"
	redeliveryQueue    = "orb.redelivery"
	redeliveryExchange = "orb.redelivery"
	waitExchange       = "orb.wait"
	waitQueue          = "orb.wait"
	directExchangeType = "direct"

	expiredReason = "expired"

	metadataDeadLetterExchange   = "x-dead-letter-exchange"
	metadataDeadLetterRoutingKey = "x-dead-letter-routing-key"
	metadataDeath                = "x-death"
	metadataFirstDeathQueue      = "x-first-death-queue"
	metadataFirstDeathReason     = "x-first-death-reason"
	metadataRedeliveryCount      = "orb-redelivery-count"
	metadataQueue                = "orb-queue"
	metadataExpiration           = "expiration"
)

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	URI                        string
	MaxConnectRetries          uint64
	MaxConnectionSubscriptions int
	MaxRedeliveryAttempts      int
	RedeliveryMultiplier       float64
	RedeliveryInitialInterval  time.Duration
	MaxRedeliveryInterval      time.Duration
}

type closeable interface {
	Close() error
}

type subscriber interface {
	closeable
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

type initializingSubscriber interface {
	subscriber
	SubscribeInitialize(topic string) error
}

type publisher interface {
	closeable
	Publish(topic string, messages ...*message.Message) error
}

type subscriberFactory = func() (initializingSubscriber, error)

type publisherFactory = func() (publisher, error)

// PubSub implements a publisher/subscriber that connects to an AMQP-compatible message queue.
type PubSub struct {
	*lifecycle.Lifecycle
	Config

	amqpConfig                  amqp.Config
	amqpRedeliveryConfig        amqp.Config
	amqpWaitConfig              amqp.Config
	subscriber                  subscriber
	publisher                   publisher
	redeliverySubscriber        subscriber
	waitSubscriber              initializingSubscriber
	waitPublisher               publisher
	pools                       []*pooledSubscriber
	mutex                       sync.RWMutex
	subscriberFactory           subscriberFactory
	createPublisher             publisherFactory
	redeliverySubscriberFactory subscriberFactory
	waitSubscriberFactory       subscriberFactory
	createWaitPublisher         publisherFactory
	redeliveryChan              <-chan *message.Message
}

// New returns a new AMQP publisher/subscriber.
func New(cfg Config) *PubSub {
	cfg = initConfig(cfg)

	p := &PubSub{
		Config:               cfg,
		amqpConfig:           newQueueConfig(cfg.URI),
		amqpRedeliveryConfig: newRedeliveryQueueConfig(cfg.URI),
		amqpWaitConfig:       newWaitQueueConfig(cfg.URI),
	}

	p.Lifecycle = lifecycle.New("amqp",
		lifecycle.WithStart(p.start),
		lifecycle.WithStop(p.stop))

	p.subscriberFactory = func() (initializingSubscriber, error) {
		return amqp.NewSubscriber(p.amqpConfig, wmlogger.New())
	}

	p.createPublisher = func() (publisher, error) {
		return amqp.NewPublisher(p.amqpConfig, wmlogger.New())
	}

	p.redeliverySubscriberFactory = func() (initializingSubscriber, error) {
		return amqp.NewSubscriber(p.amqpRedeliveryConfig, wmlogger.New())
	}

	p.waitSubscriberFactory = func() (initializingSubscriber, error) {
		return amqp.NewSubscriber(p.amqpWaitConfig, wmlogger.New())
	}

	p.createWaitPublisher = func() (publisher, error) {
		return amqp.NewPublisher(p.amqpWaitConfig, wmlogger.New())
	}

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

	if err := p.waitPublisher.Close(); err != nil {
		logger.Warnf("Error closing wait publisher: %s", err)
	}

	logger.Debugf("Closing subscriber...")

	if err := p.subscriber.Close(); err != nil {
		logger.Warnf("Error closing subscriber: %s", err)
	}

	if err := p.redeliverySubscriber.Close(); err != nil {
		logger.Warnf("Error closing redelivery subscriber: %s", err)
	}

	if err := p.waitSubscriber.Close(); err != nil {
		logger.Warnf("Error closing wait subscriber: %s", err)
	}

	logger.Debugf("Closing pools...")

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, s := range p.pools {
		s.stop()
	}
}

func (p *PubSub) start() {
	logger.Infof("Connecting to message queue at %s", extractEndpoint(p.amqpConfig.Connection.AmqpURI))

	maxRetries := p.MaxConnectRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxConnectRetries
	}

	err := backoff.RetryNotify(
		func() error {
			return p.connect()
		},
		backoff.WithMaxRetries(newConnectBackOff(), maxRetries),
		func(err error, duration time.Duration) {
			logger.Debugf("Error connecting to AMQP service %s after %s: %s. Retrying...",
				extractEndpoint(p.amqpConfig.Connection.AmqpURI), duration, err)
		},
	)
	if err != nil {
		panic(fmt.Sprintf("Unable to connect to message queue after %d attempts", maxRetries))
	}

	retryChan, err := p.redeliverySubscriber.Subscribe(context.Background(), redeliveryQueue)
	if err != nil {
		panic(fmt.Sprintf("Unable to subscribe to queue [%s]: %s", redeliveryQueue, err))
	}

	p.redeliveryChan = retryChan

	// Initialize the wait queue so that it is created. This queue contains all messages that
	// need to wait for redelivery. There are actually no subscribers to this queue. Messages in
	// this queue have an expiration time, so when the message expires, it is automatically placed
	// back on the redelivery queue.
	err = p.waitSubscriber.SubscribeInitialize(waitQueue)
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize to initialize queue [%s]: %s", redeliveryQueue, err))
	}

	go p.processRedeliveryQueue()

	logger.Infof("Successfully connected to message queue: %s", extractEndpoint(p.amqpConfig.Connection.AmqpURI))
}

func (p *PubSub) connect() error {
	pub, err := p.createPublisher()
	if err != nil {
		return err
	}

	p.subscriber = newSubscriberMgr(p.MaxConnectionSubscriptions, p.subscriberFactory)
	p.publisher = pub

	p.redeliverySubscriber = newSubscriberMgr(p.MaxConnectionSubscriptions, p.redeliverySubscriberFactory)

	pub, err = p.createWaitPublisher()
	if err != nil {
		return err
	}

	p.waitSubscriber = newSubscriberMgr(p.MaxConnectionSubscriptions, p.waitSubscriberFactory)
	p.waitPublisher = pub

	return nil
}

/*
processRedeliveryQueue processes messages from the 'redelivery' queue.
The 'redelivery' queue is configured as the 'dead-letter-queue' for all queues in Orb. When a message is rejected by a
subscriber, it is automatically sent to the 'redelivery' queue. The first time a message is rejected, the redelivery
handler immediately redelivers the message to the original destination queue. If the message is rejected again, it is
posted to a 'wait' queue and is given an expiration. The 'wait' queue has no subscribers, so the message will sit there
until it expires. The 'redelivery' queue is also configured as the 'dead-letter-queue' for the 'wait' queue, so when the
message expires, it is automatically sent back to the 'redelivery' queue and this handler processes the message again.
If the message metadata, 'reason', is set to "expired" then it is posted to the original destination queue, otherwise
(if reason is "rejected") it is posted back to the 'wait' queue with a bigger expiration. This process repeats until the
maximum number of redelivery attempts has been reached, at which point redelivery for the message is aborted.
*/
func (p *PubSub) processRedeliveryQueue() {
	logger.Infof("Starting message redelivery listener")

	for msg := range p.redeliveryChan {
		p.handleRedelivery(msg)
	}

	logger.Infof("Message redelivery listener stopped")
}

func (p *PubSub) handleRedelivery(msg *message.Message) {
	logger.Debugf("Got new RETRY message [%s], Metadata: %s, Payload %s",
		msg.UUID, msg.Metadata, msg.Payload)

	queue, err := getQueue(msg)
	if err != nil {
		logger.Warnf("Error resolving queue for message [%s]: %s. Message will not be redelivered.", msg.UUID, err)

		msg.Ack()

		return
	}

	redeliveryAttempts := getRedeliveryAttempts(msg)

	if redeliveryAttempts < p.MaxRedeliveryAttempts {
		err = p.redeliver(msg, queue, redeliveryAttempts)
		if err != nil {
			logger.Errorf("Error redelivering message [%s]: %s. The message will be nacked and retried.", msg.UUID, err)

			// Nack the message so that it may be retried.
			msg.Nack()

			return
		}
	} else {
		logger.Errorf("Message [%s] will not be redelivered to queue [%s] since it has already been redelivered %d times",
			msg.UUID, queue, redeliveryAttempts)
	}

	msg.Ack()
}

func (p *PubSub) redeliver(msg *message.Message, queue string, redeliveryAttempts int) error {
	// Publish the message immediately on the first attempt and after every expiration.
	if redeliveryAttempts == 0 || msg.Metadata[metadataFirstDeathReason] == expiredReason {
		redeliveryAttempts++

		err := p.publisher.Publish(queue,
			newMessage(msg,
				withQueue(queue),
				withRedeliveryAttempts(redeliveryAttempts),
			),
		)
		if err != nil {
			return fmt.Errorf("publish message to queue [%s]: %w", queue, err)
		}

		logger.Infof("Successfully posted message [%s] for redelivery to queue [%s]", msg.UUID, queue)

		return nil
	}

	expiration := p.getRedeliveryInterval(redeliveryAttempts)

	// Post the message to the wait queue with the given expiration so that it isn't immediately redelivered.
	err := p.waitPublisher.Publish(waitQueue,
		newMessage(msg,
			withQueue(queue),
			withExpiration(expiration),
		),
	)
	if err != nil {
		return fmt.Errorf("publish message to queue [%s]: %w", waitQueue, err)
	}

	logger.Infof("Successfully posted message [%s] to queue [%s] with expiration %s for redelivery attempt %d",
		msg.UUID, waitQueue, expiration, redeliveryAttempts)

	return nil
}

func (p *PubSub) getRedeliveryInterval(attempts int) time.Duration {
	if attempts == 0 {
		return 0
	}

	if attempts == 1 {
		return p.RedeliveryInitialInterval
	}

	interval := time.Duration(float64(p.RedeliveryInitialInterval) * math.Pow(p.RedeliveryMultiplier, float64(attempts-1)))

	if interval > p.MaxRedeliveryInterval {
		interval = p.MaxRedeliveryInterval
	}

	return interval
}

func newConnectBackOff() backoff.BackOff {
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
	subscriber    initializingSubscriber
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

func (m *subscriberConnectionMgr) SubscribeInitialize(topic string) error {
	s, err := m.get()
	if err != nil {
		return err
	}

	return s.SubscribeInitialize(topic)
}

func (m *subscriberConnectionMgr) get() (initializingSubscriber, error) {
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

// extractEndpoint returns the endpoint of the AMQP URL, i.e. everything after @.
func extractEndpoint(amqpURL string) string {
	i := strings.Index(amqpURL, "://")
	if i < 0 {
		return ""
	}

	path := amqpURL[i+3:]

	j := strings.Index(path, "@")
	if j < 0 {
		return path
	}

	return path[j+1:]
}

func getRedeliveryAttempts(msg *message.Message) int {
	var count int

	countValue, ok := msg.Metadata[metadataRedeliveryCount]
	if ok {
		c, err := strconv.ParseInt(countValue, 10, 0)
		if err != nil {
			logger.Warnf("Message [%s] - Metadata [%s] is not a valid int. Redelivery count will be set to 0: %w",
				msg.UUID, metadataRedeliveryCount)
		} else {
			count = int(c)
		}
	}

	return count
}

func getQueue(msg *message.Message) (string, error) {
	queue, ok := msg.Metadata[metadataQueue]
	if ok {
		return queue, nil
	}

	queue, ok = msg.Metadata[metadataFirstDeathQueue]
	if ok {
		return queue, nil
	}

	logger.Warnf("Message [%s] - Metadata [%s] not found. Message will not be redelivered.",
		msg.UUID, metadataFirstDeathQueue)

	return "", fmt.Errorf("metadata not found: %s", metadataFirstDeathReason)
}

type messageOptions struct {
	queue              string
	expiration         time.Duration
	redeliveryAttempts int
}

type messageOpt func(*messageOptions)

func withQueue(queue string) messageOpt {
	return func(options *messageOptions) {
		options.queue = queue
	}
}

func withExpiration(expiration time.Duration) messageOpt {
	return func(options *messageOptions) {
		options.expiration = expiration
	}
}

func withRedeliveryAttempts(attempts int) messageOpt {
	return func(options *messageOptions) {
		options.redeliveryAttempts = attempts
	}
}

func newMessage(msg *message.Message, opts ...messageOpt) *message.Message {
	options := &messageOptions{}

	for _, opt := range opts {
		opt(options)
	}

	newMsg := msg.Copy()

	// The metadata containing x-death info must be deleted since an error occurs when posting with this metadata.
	delete(newMsg.Metadata, metadataDeath)

	newMsg.Metadata.Set(metadataQueue, options.queue)

	if options.expiration > 0 {
		newMsg.Metadata.Set(metadataExpiration, options.expiration.String())
	} else {
		delete(newMsg.Metadata, metadataExpiration)
	}

	if options.redeliveryAttempts > 0 {
		newMsg.Metadata.Set(metadataRedeliveryCount, strconv.FormatInt(int64(options.redeliveryAttempts), 10))
	}

	return newMsg
}

func newQueueConfig(amqpURI string) amqp.Config {
	queueConfig := newDefaultQueueConfig(amqpURI)
	queueConfig.Exchange = newAMQPExchangeConfig(exchange)
	queueConfig.Queue = newAMQPQueueConfig(samqp.Table{
		metadataDeadLetterRoutingKey: redeliveryQueue,
		metadataDeadLetterExchange:   redeliveryExchange,
	})

	return queueConfig
}

func newRedeliveryQueueConfig(amqpURI string) amqp.Config {
	queueConfig := newDefaultQueueConfig(amqpURI)
	queueConfig.Exchange = newAMQPExchangeConfig(redeliveryExchange)
	queueConfig.Consume = amqp.ConsumeConfig{
		Qos:             amqp.QosConfig{PrefetchCount: 1},
		NoRequeueOnNack: false, // Ensure that the message is re-queued if the server goes down before it is Acked.
	}

	return queueConfig
}

func newWaitQueueConfig(amqpURI string) amqp.Config {
	queueConfig := newDefaultQueueConfig(amqpURI)
	queueConfig.Exchange = newAMQPExchangeConfig(waitExchange)
	queueConfig.Queue = newAMQPQueueConfig(samqp.Table{
		metadataDeadLetterRoutingKey: redeliveryQueue,
		metadataDeadLetterExchange:   redeliveryExchange,
	})

	return queueConfig
}

func newDefaultQueueConfig(amqpURI string) amqp.Config {
	return amqp.Config{
		Connection: amqp.ConnectionConfig{AmqpURI: amqpURI},
		Marshaler:  &DefaultMarshaler{},
		Queue:      newAMQPQueueConfig(nil),
		QueueBind: amqp.QueueBindConfig{
			GenerateRoutingKey: func(queue string) string { return queue },
		},
		Publish: amqp.PublishConfig{
			GenerateRoutingKey: func(queue string) string { return queue },
		},
		Consume: amqp.ConsumeConfig{
			Qos:             amqp.QosConfig{PrefetchCount: 1},
			NoRequeueOnNack: true,
		},
		TopologyBuilder: &amqp.DefaultTopologyBuilder{},
	}
}

func newAMQPExchangeConfig(exchange string) amqp.ExchangeConfig {
	return amqp.ExchangeConfig{
		GenerateName: func(topic string) string {
			return exchange
		},
		Type:    directExchangeType,
		Durable: true,
	}
}

func newAMQPQueueConfig(args samqp.Table) amqp.QueueConfig {
	return amqp.QueueConfig{
		GenerateName: amqp.GenerateQueueNameTopicName,
		Durable:      true,
		Arguments:    args,
	}
}

func initConfig(cfg Config) Config {
	if cfg.MaxConnectionSubscriptions == 0 {
		cfg.MaxConnectionSubscriptions = defaultMaxConnectionSubscriptions
	}

	if cfg.MaxRedeliveryAttempts == 0 {
		cfg.MaxRedeliveryAttempts = defaultMaxRedeliveryAttempts
	}

	if cfg.RedeliveryMultiplier == 0 {
		cfg.RedeliveryMultiplier = defaultRedeliveryMultiplier
	}

	if cfg.RedeliveryInitialInterval == 0 {
		cfg.RedeliveryInitialInterval = defaultRedeliveryInitialInterval
	}

	if cfg.MaxRedeliveryInterval == 0 {
		cfg.MaxRedeliveryInterval = defaultMaxRedeliveryInterval
	}

	return cfg
}
