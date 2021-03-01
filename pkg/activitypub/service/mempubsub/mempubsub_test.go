/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mempubsub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"

	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

func TestNew(t *testing.T) {
	ps := New("service1", DefaultConfig())
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

	require.NoError(t, ps.Close())
}
