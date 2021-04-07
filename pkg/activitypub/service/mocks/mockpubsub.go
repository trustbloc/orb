/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"

	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

const (
	maxBufferSize = 5
	timeout       = 100 * time.Millisecond
)

// MockPubSub implements a mock publisher-subscriber.
type MockPubSub struct {
	Err     error
	MsgChan map[string]chan *message.Message
	mutex   sync.RWMutex
	Timeout time.Duration
}

// NewPubSub returns a mock publisher-subscriber.
func NewPubSub() *MockPubSub {
	return &MockPubSub{
		MsgChan: make(map[string]chan *message.Message, 10),
		Timeout: timeout,
	}
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

	m.mutex.RLock()
	msgChan := m.MsgChan[topic]
	m.mutex.RUnlock()

	if msgChan == nil {
		return fmt.Errorf("service is closed")
	}

	for _, msg := range messages {
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

	m.mutex.Lock()

	for _, m := range m.MsgChan {
		close(m)
	}

	m.MsgChan = nil

	m.mutex.Unlock()

	return nil
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
	m.mutex.RLock()
	msgChan := m.MsgChan[service.UndeliverableTopic]
	m.mutex.RUnlock()

	msgChan <- msg
}
