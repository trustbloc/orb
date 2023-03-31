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
	"sync/atomic"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cenkalti/backoff"
	ramqp "github.com/rabbitmq/amqp091-go"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

const loggerModule = "pubsub"

var logger = log.New(loggerModule)

const (
	defaultMaxConnectRetries                 = 25
	defaultMaxConnectInterval                = 5 * time.Second
	defaultMaxConnectElapsedTime             = 3 * time.Minute
	defaultMaxConnectionSubscriptions        = 1000
	defaultWaitQueuePublisherChannelPoolSize = 5

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

	base10 = 10
)

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	URI                       string
	MaxConnectRetries         int
	MaxConnectionChannels     int
	MaxRedeliveryAttempts     int
	RedeliveryMultiplier      float64
	RedeliveryInitialInterval time.Duration
	MaxRedeliveryInterval     time.Duration
	PublisherChannelPoolSize  int
	PublisherConfirmDelivery  bool
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

type connMgr interface {
	close() error
	getConnection(shared bool) (connection, error)
	isConnected() bool
}

type subscriberFactory = func(conn connection) (initializingSubscriber, error)

type publisherFactory = func(conn connection) (publisher, error)

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
	createPublisher             createPublisherFunc
	redeliverySubscriberFactory subscriberFactory
	waitSubscriberFactory       subscriberFactory
	createWaitPublisher         publisherFactory
	redeliveryChan              <-chan *message.Message
	connMgr                     connMgr
}

// New returns a new AMQP publisher/subscriber.
func New(cfg Config) *PubSub {
	cfg = initConfig(cfg)

	p := &PubSub{
		Config:               cfg,
		connMgr:              newConnectionMgr(amqp.ConnectionConfig{AmqpURI: cfg.URI}, cfg.MaxConnectionChannels),
		amqpConfig:           newQueueConfig(cfg),
		amqpRedeliveryConfig: newRedeliveryQueueConfig(cfg),
		amqpWaitConfig:       newWaitQueueConfig(cfg),
		createPublisher:      createPublisher,
	}

	p.Lifecycle = lifecycle.New("amqp",
		lifecycle.WithStart(p.start),
		lifecycle.WithStop(p.stop))

	p.subscriberFactory = func(conn connection) (initializingSubscriber, error) {
		return amqp.NewSubscriberWithConnection(p.amqpConfig, wmlogger.New(), conn.amqpConnection())
	}

	p.redeliverySubscriberFactory = func(conn connection) (initializingSubscriber, error) {
		return amqp.NewSubscriberWithConnection(p.amqpRedeliveryConfig, wmlogger.New(), conn.amqpConnection())
	}

	p.waitSubscriberFactory = func(conn connection) (initializingSubscriber, error) {
		return amqp.NewSubscriberWithConnection(p.amqpWaitConfig, wmlogger.New(), conn.amqpConnection())
	}

	p.createWaitPublisher = func(conn connection) (publisher, error) {
		return amqp.NewPublisherWithConnection(p.amqpWaitConfig, wmlogger.New(), conn.amqpConnection())
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

// IsConnected return true if connected to the AMQP server.
func (p *PubSub) IsConnected() bool {
	return p.connMgr.isConnected()
}

// SubscribeWithOpts subscribes to a topic using the given options, and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error) {
	if p.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	options := getOptions(opts)

	if options.PoolSize <= 1 {
		logger.Debug("Subscribing to topic", log.WithTopic(topic))

		return p.subscriber.Subscribe(ctx, topic)
	}

	logger.Debug("Creating subscriber pool", log.WithTopic(topic), logfields.WithSubscriberPoolSize(options.PoolSize))

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

	logger.Debug("Publishing messages", log.WithTopic(topic))

	if err := p.publisher.Publish(topic, messages...); err != nil {
		for _, msg := range messages {
			logger.Error("Error publishing message", logfields.WithMessageID(msg.UUID), log.WithTopic(topic))
		}

		return errors.NewTransientf("publish messages to topic [%s]: %w", topic, err)
	}

	return nil
}

// PublishWithOpts publishes a message to a topic using the supplied options.
func (p *PubSub) PublishWithOpts(topic string, msg *message.Message, opts ...spi.Option) error {
	if p.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	if options := getOptions(opts); options.DeliveryDelay > 0 {
		return p.publishWithDelay(topic, msg, options.DeliveryDelay)
	}

	return p.Publish(topic, msg)
}

func (p *PubSub) publishWithDelay(topic string, msg *message.Message, delay time.Duration) error {
	logger.Debug("Publishing message", logfields.WithMessageID(msg.UUID),
		log.WithTopic(topic), logfields.WithDeliveryDelay(delay))

	// Post the message to the wait queue with the given expiration so that it isn't immediately redelivered.
	err := p.waitPublisher.Publish(waitQueue,
		newMessage(msg,
			withQueue(topic),
			withExpiration(delay),
		),
	)
	if err != nil {
		logger.Error("Error publishing message to wait queue", logfields.WithMessageID(msg.UUID), log.WithError(err))

		return errors.NewTransientf("publish message to wait queue: %w", err)
	}

	logger.Debug("Successfully published message", logfields.WithMessageID(msg.UUID),
		log.WithTopic(topic), logfields.WithDeliveryDelay(delay))

	return nil
}

// Close stops the publisher/subscriber.
func (p *PubSub) Close() error {
	p.Stop()

	return nil
}

func (p *PubSub) stop() {
	logger.Debug("Closing publisher...")

	if err := p.publisher.Close(); err != nil {
		logger.Warn("Error closing publisher", log.WithError(err))
	}

	if err := p.waitPublisher.Close(); err != nil {
		logger.Warn("Error closing wait publisher", log.WithError(err))
	}

	logger.Debug("Closing subscriber...")

	if err := p.subscriber.Close(); err != nil {
		logger.Warn("Error closing subscriber", log.WithError(err))
	}

	if err := p.redeliverySubscriber.Close(); err != nil {
		logger.Warn("Error closing redelivery subscriber", log.WithError(err))
	}

	if err := p.waitSubscriber.Close(); err != nil {
		logger.Warn("Error closing wait subscriber", log.WithError(err))
	}

	if err := p.connMgr.close(); err != nil {
		logger.Warn("Error closing connection manager", log.WithError(err))
	}

	logger.Debug("Closing pools...")

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, s := range p.pools {
		s.stop()
	}
}

func (p *PubSub) start() {
	logger.Info("Connecting to message queue", log.WithAddress(extractEndpoint(p.amqpConfig.Connection.AmqpURI)))

	maxRetries := p.MaxConnectRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxConnectRetries
	}

	err := backoff.RetryNotify(
		func() error {
			return p.connect()
		},
		backoff.WithMaxRetries(newConnectBackOff(), uint64(maxRetries)),
		func(err error, duration time.Duration) {
			logger.Debug("Error connecting to AMQP service. Will retry with backoff...",
				log.WithAddress(extractEndpoint(p.amqpConfig.Connection.AmqpURI)),
				logfields.WithBackoff(duration), log.WithError(err))
		},
	)
	if err != nil {
		panic(fmt.Sprintf("Unable to connect to message queue after %d attempts: %s", maxRetries, err))
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
		panic(fmt.Sprintf("Unable to initialize queue [%s]: %s", waitQueue, err))
	}

	go p.processRedeliveryQueue()

	logger.Info("Successfully connected to AMQP service",
		log.WithAddress(extractEndpoint(p.amqpConfig.Connection.AmqpURI)))
}

func (p *PubSub) connect() error {
	pubPool, err := newPublisherPool(p.connMgr, p.MaxConnectionChannels, &p.amqpConfig, p.createPublisher)
	if err != nil {
		return err
	}

	p.publisher = pubPool

	p.subscriber = newSubscriberMgr(p.connMgr, p.subscriberFactory)

	p.redeliverySubscriber = newSubscriberMgr(p.connMgr, p.redeliverySubscriberFactory)

	conn, err := p.connMgr.getConnection(true)
	if err != nil {
		return fmt.Errorf("get connection: %w", err)
	}

	pub, err := p.createWaitPublisher(conn)
	if err != nil {
		return err
	}

	p.waitSubscriber = newSubscriberMgr(p.connMgr, p.waitSubscriberFactory)
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
	logger.Info("Starting message redelivery listener")

	for msg := range p.redeliveryChan {
		p.handleRedelivery(msg)
	}

	logger.Info("Message redelivery listener stopped")
}

func (p *PubSub) handleRedelivery(msg *message.Message) {
	logger.Debug("Got new RETRY message", logfields.WithMessageID(msg.UUID),
		logfields.WithMetadata(msg.Metadata), logfields.WithData(msg.Payload))

	queue, err := getQueue(msg)
	if err != nil {
		logger.Warn("Error resolving queue for message. Message will not be redelivered.",
			logfields.WithMessageID(msg.UUID), log.WithError(err))

		msg.Ack()

		return
	}

	redeliveryAttempts := getRedeliveryAttempts(msg)

	if redeliveryAttempts < p.MaxRedeliveryAttempts {
		err = p.redeliver(msg, queue, redeliveryAttempts)
		if err != nil {
			logger.Error("Error redelivering message. The message will be nacked and retried.",
				logfields.WithMessageID(msg.UUID), log.WithError(err))

			// Nack the message so that it may be retried.
			msg.Nack()

			return
		}
	} else {
		logger.Error("Message will not be redelivered since the maximum delivery attempts has been reached",
			logfields.WithMessageID(msg.UUID), log.WithTopic(queue), logfields.WithDeliveryAttempts(redeliveryAttempts+1))
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

		logger.Info("Successfully posted message for redelivery", logfields.WithMessageID(msg.UUID),
			log.WithTopic(queue), logfields.WithDeliveryAttempts(redeliveryAttempts))

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
		return fmt.Errorf("publish message to queue [%s] with expiration %s for redelivery attempt %d: %w",
			waitQueue, expiration, redeliveryAttempts, err)
	}

	logger.Info("Successfully posted message", logfields.WithMessageID(msg.UUID), log.WithTopic(waitQueue),
		logfields.WithDeliveryDelay(expiration), logfields.WithDeliveryAttempts(redeliveryAttempts+1))

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

func createPublisher(cfg *amqp.Config, conn connection) (publisher, error) {
	pub, err := amqp.NewPublisherWithConnection(*cfg, wmlogger.New(), conn.amqpConnection())
	if err != nil {
		return nil, fmt.Errorf("new publisher: %w", err)
	}

	return pub, nil
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

type connection interface {
	amqpConnection() *amqp.ConnectionWrapper
	incrementChannelCount() uint32
	numChannels() uint32
}

type connectionMgr struct {
	channelLimit uint32
	current      *connectionWrapper
	connections  []*connectionWrapper
	mutex        sync.RWMutex
	config       amqp.ConnectionConfig
}

func newConnectionMgr(cfg amqp.ConnectionConfig, limit int) *connectionMgr {
	return &connectionMgr{
		config:       cfg,
		channelLimit: uint32(limit),
	}
}

func (m *connectionMgr) getConnection(shared bool) (connection, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !shared {
		conn, err := amqp.NewConnection(m.config, wmlogger.New())
		if err != nil {
			return nil, fmt.Errorf("create connection: %w", err)
		}

		c := &connectionWrapper{conn: conn}

		m.connections = append(m.connections, c)

		logger.Info("Created new connection.", logfields.WithTotal(len(m.connections)))

		return c, nil
	}

	if m.current == nil || m.current.numChannels() >= m.channelLimit {
		conn, err := amqp.NewConnection(m.config, wmlogger.New())
		if err != nil {
			return nil, fmt.Errorf("create connection: %w", err)
		}

		newCurrent := &connectionWrapper{conn: conn}

		m.connections = append(m.connections, newCurrent)
		m.current = newCurrent

		logger.Info("Created new shared connection.", logfields.WithTotal(len(m.connections)))
	}

	numChannels := m.current.incrementChannelCount()

	logger.Debug("Incremented channel count for current connection.", logfields.WithTotal(int(numChannels)))

	return m.current, nil
}

func (m *connectionMgr) isConnected() bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.current != nil && m.current.amqpConnection().IsConnected()
}

func (m *connectionMgr) close() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logger.Info("Closing connections", logfields.WithTotal(len(m.connections)))

	for _, c := range m.connections {
		if err := c.amqpConnection().Close(); err != nil {
			logger.Warn("Error closing connection", log.WithError(err))
		}
	}

	return nil
}

type connectionWrapper struct {
	conn     *amqp.ConnectionWrapper
	channels uint32
}

func (c *connectionWrapper) amqpConnection() *amqp.ConnectionWrapper {
	return c.conn
}

func (c *connectionWrapper) incrementChannelCount() uint32 {
	return atomic.AddUint32(&c.channels, 1)
}

func (c *connectionWrapper) numChannels() uint32 {
	return atomic.LoadUint32(&c.channels)
}

type subscriberInfo struct {
	conn       connection
	subscriber initializingSubscriber
}

type subscriberMgr struct {
	connMgr          connMgr
	createSubscriber subscriberFactory
	mutex            sync.RWMutex
	current          *subscriberInfo
	subscribers      []*subscriberInfo
}

func newSubscriberMgr(connMgr connMgr, factory subscriberFactory) *subscriberMgr {
	return &subscriberMgr{
		connMgr:          connMgr,
		createSubscriber: factory,
	}
}

func (m *subscriberMgr) Close() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logger.Info("Closing subscribers", logfields.WithTotal(len(m.subscribers)))

	for _, s := range m.subscribers {
		if err := s.subscriber.Close(); err != nil {
			logger.Warn("Error closing subscriber", log.WithError(err))
		}
	}

	return nil
}

func (m *subscriberMgr) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	s, err := m.get()
	if err != nil {
		return nil, err
	}

	return s.Subscribe(ctx, topic)
}

func (m *subscriberMgr) SubscribeInitialize(topic string) error {
	s, err := m.get()
	if err != nil {
		return err
	}

	return s.SubscribeInitialize(topic)
}

func (m *subscriberMgr) get() (initializingSubscriber, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	conn, err := m.connMgr.getConnection(true)
	if err != nil {
		return nil, fmt.Errorf("get connection for subscriber: %w", err)
	}

	if m.current == nil || conn != m.current.conn {
		s, err := m.createSubscriber(conn)
		if err != nil {
			return nil, err
		}

		m.current = &subscriberInfo{
			subscriber: s,
			conn:       conn,
		}

		m.subscribers = append(m.subscribers, m.current)

		logger.Debug("Created a subscriber.", logfields.WithTotal(len(m.subscribers)))
	}

	logger.Debug("Incremented channel count for current connection.", logfields.WithTotal(int(conn.numChannels())))

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
		c, err := strconv.ParseInt(countValue, base10, 0)
		if err != nil {
			logger.Warn("Message metadata property is not a valid int. Redelivery count will be set to 0",
				logfields.WithMessageID(msg.UUID), logfields.WithProperty(metadataRedeliveryCount))
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

	logger.Warn("Message metadata property not found. Message will not be redelivered.",
		logfields.WithMessageID(msg.UUID), logfields.WithProperty(metadataFirstDeathQueue))

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
		newMsg.Metadata.Set(metadataRedeliveryCount, strconv.FormatInt(int64(options.redeliveryAttempts), base10))
	}

	return newMsg
}

func newQueueConfig(cfg Config) amqp.Config {
	queueConfig := newDefaultQueueConfig(cfg)
	queueConfig.Exchange = newAMQPExchangeConfig(exchange)
	queueConfig.Queue = newAMQPQueueConfig(ramqp.Table{
		metadataDeadLetterRoutingKey: redeliveryQueue,
		metadataDeadLetterExchange:   redeliveryExchange,
	})

	return queueConfig
}

func newRedeliveryQueueConfig(cfg Config) amqp.Config {
	queueConfig := newDefaultQueueConfig(cfg)
	queueConfig.Exchange = newAMQPExchangeConfig(redeliveryExchange)
	queueConfig.Consume = amqp.ConsumeConfig{
		Qos:             amqp.QosConfig{PrefetchCount: 1},
		NoRequeueOnNack: false, // Ensure that the message is re-queued if the server goes down before it is Acked.
	}

	return queueConfig
}

func newWaitQueueConfig(cfg Config) amqp.Config {
	queueConfig := newDefaultQueueConfig(cfg)
	queueConfig.Exchange = newAMQPExchangeConfig(waitExchange)
	queueConfig.Queue = newAMQPQueueConfig(ramqp.Table{
		metadataDeadLetterRoutingKey: redeliveryQueue,
		metadataDeadLetterExchange:   redeliveryExchange,
	})
	queueConfig.Publish.ChannelPoolSize = defaultWaitQueuePublisherChannelPoolSize

	return queueConfig
}

func newDefaultQueueConfig(cfg Config) amqp.Config {
	return amqp.Config{
		Connection: amqp.ConnectionConfig{AmqpURI: cfg.URI},
		Marshaler:  &DefaultMarshaler{},
		Queue:      newAMQPQueueConfig(nil),
		QueueBind: amqp.QueueBindConfig{
			GenerateRoutingKey: func(queue string) string { return queue },
		},
		Publish: amqp.PublishConfig{
			GenerateRoutingKey: func(queue string) string { return queue },
			ChannelPoolSize:    cfg.PublisherChannelPoolSize,
			ConfirmDelivery:    cfg.PublisherConfirmDelivery,
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

func newAMQPQueueConfig(args ramqp.Table) amqp.QueueConfig {
	return amqp.QueueConfig{
		GenerateName: amqp.GenerateQueueNameTopicName,
		Durable:      true,
		Arguments:    args,
	}
}

func initConfig(cfg Config) Config {
	if cfg.MaxConnectionChannels == 0 {
		cfg.MaxConnectionChannels = defaultMaxConnectionSubscriptions
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

func getOptions(opts []spi.Option) *spi.Options {
	options := &spi.Options{}

	for _, opt := range opts {
		opt(options)
	}

	return options
}
