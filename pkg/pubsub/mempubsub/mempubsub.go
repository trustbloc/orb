/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mempubsub

import (
	"context"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("pubsub")

const (
	defaultTimeout     = 10 * time.Second
	defaultConcurrency = 20
	defaultBufferSize  = 20
)

// Config holds the configuration for the publisher/subscriber.
type Config struct {
	// Timeout is the time that we should wait for an Ack or a Nack.
	Timeout time.Duration

	// Concurrency specifies the maximum number of concurrent requests.
	Concurrency int

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:     defaultTimeout,
		Concurrency: defaultConcurrency,
		BufferSize:  defaultBufferSize,
	}
}

// PubSub implements a publisher/subscriber using Go channels. This implementation
// works only on a single node, i.e. handlers are not distributed. In order to distribute
// the load across a cluster, a persistent message queue (such as RabbitMQ or Kafka) should
// instead be used.
type PubSub struct {
	*lifecycle.Lifecycle
	Config

	msgChansByTopic map[string][]chan *message.Message
	mutex           sync.RWMutex
	publishChan     chan *entry
	ackChan         chan *message.Message
	doneChan        chan struct{}
}

type entry struct {
	topic    string
	messages []*message.Message
}

// New returns a new publisher/subscriber.
func New(cfg Config) *PubSub {
	m := &PubSub{
		Config:          cfg,
		msgChansByTopic: make(map[string][]chan *message.Message),
		publishChan:     make(chan *entry, cfg.BufferSize),
		ackChan:         make(chan *message.Message, cfg.Concurrency),
		doneChan:        make(chan struct{}),
	}

	m.Lifecycle = lifecycle.New("httpsubscriber", lifecycle.WithStop(m.stop))

	go m.processMessages()
	go m.processAcks()

	// Start the service immediately.
	m.Start()

	return m
}

// Close closes all resources.
func (p *PubSub) Close() error {
	p.Stop()

	return nil
}

// IsConnected return true is connected.
func (p *PubSub) IsConnected() bool {
	return true
}

func (p *PubSub) stop() {
	logger.Infof("Stopping publisher/subscriber...")

	p.doneChan <- struct{}{}

	logger.Debugf("... waiting for publisher to stop...")

	<-p.doneChan

	logger.Debugf("... closing subscriber channels...")

	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, msgChans := range p.msgChansByTopic {
		for _, msgChan := range msgChans {
			close(msgChan)
		}
	}

	p.msgChansByTopic = nil

	close(p.ackChan)

	logger.Infof("... publisher/subscriber stopped.")
}

// Subscribe subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	return p.SubscribeWithOpts(ctx, topic)
}

// SubscribeWithOpts subscribes to a topic and returns the Go channel over which messages
// are sent. The returned channel will be closed when Close() is called on this struct.
func (p *PubSub) SubscribeWithOpts(_ context.Context, topic string, _ ...spi.Option) (<-chan *message.Message, error) {
	if p.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	logger.Debugf("Subscribing to topic [%s]", topic)

	p.mutex.Lock()
	defer p.mutex.Unlock()

	msgChan := make(chan *message.Message, p.BufferSize)

	p.msgChansByTopic[topic] = append(p.msgChansByTopic[topic], msgChan)

	return msgChan, nil
}

// Publish publishes the given messages to the given topic. This function returns
// immediately after sending the messages to the Go channel(s), although it will
// block if the concurrency limit (defined by Config.Concurrency) has been reached.
func (p *PubSub) Publish(topic string, messages ...*message.Message) error {
	if p.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	p.publishChan <- &entry{
		topic:    topic,
		messages: messages,
	}

	return nil
}

// PublishWithOpts simply calls Publish since options are not supported.
func (p *PubSub) PublishWithOpts(topic string, msg *message.Message, _ ...spi.Option) error {
	return p.Publish(topic, msg)
}

func (p *PubSub) processMessages() {
	for {
		select {
		case entry := <-p.publishChan:
			p.publish(entry)

		case <-p.doneChan:
			p.doneChan <- struct{}{}

			logger.Debugf("... publisher has stopped")

			return
		}
	}
}

func (p *PubSub) processAcks() {
	for msg := range p.ackChan {
		go p.check(msg)
	}
}

func (p *PubSub) publish(entry *entry) {
	p.mutex.RLock()
	msgChans := p.msgChansByTopic[entry.topic]
	p.mutex.RUnlock()

	if len(msgChans) == 0 {
		logger.Debugf("No subscribers for topic [%s]", entry.topic)

		return
	}

	for _, msgChan := range msgChans {
		for _, m := range entry.messages {
			// Copy the message so that the Ack/Nack is specific to a subscriber
			msg := m.Copy()

			logger.Debugf("Publishing message [%s]", msg.UUID)

			msgChan <- msg
			p.ackChan <- msg
		}
	}
}

func (p *PubSub) check(msg *message.Message) {
	logger.Debugf("Checking for Ack/Nack on message [%s]", msg.UUID)

	select {
	case <-msg.Acked():
		logger.Infof("Message was successfully acknowledged [%s]", msg.UUID)

	case <-msg.Nacked():
		logger.Infof("Message was not successfully acknowledged. Posting to undeliverable queue [%s]", msg.UUID)

		p.postToUndeliverable(msg)

	case <-time.After(p.Timeout):
		logger.Warnf("Timed out after %s waiting for Ack/Nack. Posting to undeliverable queue [%s]", p.Timeout, msg.UUID)

		p.postToUndeliverable(msg)
	}
}

func (p *PubSub) postToUndeliverable(msg *message.Message) {
	p.mutex.RLock()
	msgChans := p.msgChansByTopic[spi.UndeliverableTopic]
	p.mutex.RUnlock()

	// When sending to the undeliverable queue, we don't want to block since this may result in a deadlock.
	// So if the undeliverable channel buffer is full, the send will fail and the message will be dropped.

	for _, msgChan := range msgChans {
		select {
		case msgChan <- msg:
			logger.Infof("Message was added to the undeliverable queue [%s]", msg.UUID)

		default:
			logger.Warnf("Message could not be added to the undeliverable queue and will be dropped [%s]", msg.UUID)
		}
	}
}
