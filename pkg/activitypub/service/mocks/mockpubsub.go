/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

const (
	maxBufferSize = 5
	timeout       = 100 * time.Millisecond
)

// MockPubSub implements a mock publisher-subscriber.
type MockPubSub struct {
	*lifecycle.Lifecycle

	Err               error
	MsgChan           map[string]chan *message.Message
	mutex             sync.RWMutex
	Timeout           time.Duration
	undeliverableChan chan *message.Message
	done              chan struct{}
}

// NewPubSub returns a mock publisher-subscriber.
func NewPubSub() *MockPubSub {
	m := &MockPubSub{
		MsgChan:           make(map[string]chan *message.Message),
		Timeout:           timeout,
		undeliverableChan: make(chan *message.Message, maxBufferSize),
		done:              make(chan struct{}),
	}

	m.Lifecycle = lifecycle.New("mock_pubsub", lifecycle.WithStop(m.stop))

	go m.handleUndeliverable()

	m.Start()

	return m
}

// WithError injects an error into the mock publisher-subscriber.
func (m *MockPubSub) WithError(err error) *MockPubSub {
	m.Err = err

	return m
}

// Subscribe subscribes to the given topic.
func (m *MockPubSub) Subscribe(_ context.Context, topic string) (<-chan *message.Message, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	if m.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	msgChan := make(chan *message.Message, maxBufferSize)

	m.MsgChan[topic] = msgChan

	return msgChan, nil
}

// Publish publishes the messages to the subscribers.
func (m *MockPubSub) Publish(topic string, messages ...*message.Message) error {
	if m.Err != nil {
		return m.Err
	}

	if m.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	msgChan := m.MsgChan[topic]

	for _, msg := range messages {
		// Copy the message so that the Ack/Nack is specific to a subscriber
		msg = msg.Copy()

		msgChan <- msg

		go m.check(msg)
	}

	return nil
}

// Close closes the subscriber channels.
func (m *MockPubSub) Close() error {
	if m.Err != nil {
		return m.Err
	}

	m.Stop()

	return nil
}

func (m *MockPubSub) stop() {
	close(m.undeliverableChan)

	<-m.done

	for _, msgChan := range m.MsgChan {
		close(msgChan)
	}
}

func (m *MockPubSub) handleUndeliverable() {
	for msg := range m.undeliverableChan {
		msgChan, ok := m.MsgChan[spi.UndeliverableTopic]
		if !ok {
			continue
		}

		msgChan <- msg
	}

	m.done <- struct{}{}
}

func (m *MockPubSub) check(msg *message.Message) {
	select {
	case <-msg.Acked():
	case <-msg.Nacked():
		m.postToUndeliverable(msg)
	case <-time.After(m.Timeout):
		m.postToUndeliverable(msg)
	}
}

func (m *MockPubSub) postToUndeliverable(msg *message.Message) {
	if m.State() != lifecycle.StateStarted {
		return
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	m.undeliverableChan <- msg
}
