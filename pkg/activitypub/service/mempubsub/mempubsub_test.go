/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mempubsub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"

	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

func TestPubSub_Publish(t *testing.T) {
	cfg := DefaultConfig()

	cfg.Timeout = 100 * time.Millisecond

	ps := New("service1", cfg)
	require.NotNil(t, ps)

	t.Run("Ack", func(t *testing.T) {
		msgChan, err := ps.Subscribe(context.Background(), "topic1")
		require.NoError(t, err)

		var mutex sync.Mutex
		receivedMessages := make(map[string]*message.Message)

		go func() {
			for msg := range msgChan {
				msg.Ack()

				mutex.Lock()
				receivedMessages[msg.UUID] = msg
				mutex.Unlock()
			}
		}()

		msg := message.NewMessage(watermill.NewUUID(), []byte("payload1"))

		require.NoError(t, ps.Publish("topic1", msg))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		m, ok := receivedMessages[msg.UUID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.UUID, m.UUID)
	})

	t.Run("Nack", func(t *testing.T) {
		msgChan, err := ps.Subscribe(context.Background(), "topic1")
		require.NoError(t, err)

		undeliverableChan, err := ps.Subscribe(context.Background(), service.UndeliverableTopic)
		require.NoError(t, err)

		var mutex sync.Mutex
		receivedMessages := make(map[string]*message.Message)
		undeliverableMessages := make(map[string]*message.Message)

		go func() {
			for msg := range msgChan {
				msg.Nack()

				mutex.Lock()
				receivedMessages[msg.UUID] = msg
				mutex.Unlock()
			}
		}()

		go func() {
			for msg := range undeliverableChan {
				mutex.Lock()
				undeliverableMessages[msg.UUID] = msg
				mutex.Unlock()
			}
		}()

		msg := message.NewMessage(watermill.NewUUID(), []byte("payload1"))

		require.NoError(t, ps.Publish("topic1", msg))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		m, ok := receivedMessages[msg.UUID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.UUID, m.UUID)

		mutex.Lock()
		m, ok = undeliverableMessages[msg.UUID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.UUID, m.UUID)
	})

	t.Run("Timeout", func(t *testing.T) {
		msgChan, err := ps.Subscribe(context.Background(), "topic1")
		require.NoError(t, err)

		undeliverableChan, err := ps.Subscribe(context.Background(), service.UndeliverableTopic)
		require.NoError(t, err)

		var mutex sync.Mutex
		receivedMessages := make(map[string]*message.Message)
		undeliverableMessages := make(map[string]*message.Message)

		go func() {
			for msg := range msgChan {
				// Don't Ack/Nack the message. Should timeout and
				// result in an undeliverable message.
				mutex.Lock()
				receivedMessages[msg.UUID] = msg
				mutex.Unlock()
			}
		}()

		go func() {
			for msg := range undeliverableChan {
				mutex.Lock()
				undeliverableMessages[msg.UUID] = msg
				mutex.Unlock()
			}
		}()

		msg := message.NewMessage(watermill.NewUUID(), []byte("payload1"))

		require.NoError(t, ps.Publish("topic1", msg))

		time.Sleep(1000 * time.Millisecond)

		mutex.Lock()
		m, ok := receivedMessages[msg.UUID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.UUID, m.UUID)

		mutex.Lock()
		m, ok = undeliverableMessages[msg.UUID]
		mutex.Unlock()

		require.True(t, ok)
		require.Equal(t, msg.UUID, m.UUID)
	})

	require.NoError(t, ps.Close())
}

func TestPubSub_Error(t *testing.T) {
	t.Run("Subscribe when closed -> error", func(t *testing.T) {
		ps := New("service1", DefaultConfig())
		require.NotNil(t, ps)
		require.NoError(t, ps.Close())

		msgChan, err := ps.Subscribe(context.Background(), "topic1")
		require.True(t, errors.Is(err, service.ErrNotStarted))
		require.Nil(t, msgChan)
	})

	t.Run("Publish when closed -> error", func(t *testing.T) {
		ps := New("service1", DefaultConfig())
		require.NotNil(t, ps)
		require.NoError(t, ps.Close())

		err := ps.Publish("topic1", message.NewMessage("123", nil))
		require.True(t, errors.Is(err, service.ErrNotStarted))
	})
}

func TestPubSub_Close(t *testing.T) {
	ps := New("service1", DefaultConfig())
	require.NotNil(t, ps)

	msgChan, err := ps.Subscribe(context.Background(), "topic1")
	require.NoError(t, err)

	var mutex sync.Mutex

	receivedMessages := make(map[string]*message.Message)

	go func() {
		for msg := range msgChan {
			time.Sleep(5 * time.Millisecond)
			msg.Ack()

			mutex.Lock()
			receivedMessages[msg.UUID] = msg
			mutex.Unlock()
		}
	}()

	go func() {
		for i := 0; i < 200; i++ {
			msg := message.NewMessage(watermill.NewUUID(), []byte("payload1"))

			if err := ps.Publish("topic1", msg); err != nil {
				if errors.Is(err, service.ErrNotStarted) {
					return
				}

				panic(err)
			}

			time.Sleep(5 * time.Millisecond)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Close the service while we're still publishing messages to ensure
	// we don't panic or encounter race conditions.
	require.NoError(t, ps.Close())

	mutex.Lock()
	t.Logf("Received %d messages", len(receivedMessages))
	mutex.Unlock()
}
