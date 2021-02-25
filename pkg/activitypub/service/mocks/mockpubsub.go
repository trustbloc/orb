/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"context"

	"github.com/ThreeDotsLabs/watermill/message"
)

// MockPubSub implements a mock publisher-subscriber.
type MockPubSub struct {
	Err     error
	MsgChan chan *message.Message
}

// NewPubSub returns a mock publisher-subscriber.
func NewPubSub() *MockPubSub {
	return &MockPubSub{
		MsgChan: make(chan *message.Message),
	}
}

// WithError injects an error into the mock publisher-subscriber.
func (m *MockPubSub) WithError(err error) *MockPubSub {
	m.Err = err

	return m
}

// Subscribe subscribes to the given topic.
func (m *MockPubSub) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.MsgChan, nil
}

// Publish publishes the messages to the subscribers.
func (m *MockPubSub) Publish(topic string, messages ...*message.Message) error {
	if m.Err != nil {
		return m.Err
	}

	for _, msg := range messages {
		m.MsgChan <- msg
	}

	return nil
}

// Close closes the subscriber channels.
func (m *MockPubSub) Close() error {
	if m.Err != nil {
		return m.Err
	}

	close(m.MsgChan)

	return nil
}
