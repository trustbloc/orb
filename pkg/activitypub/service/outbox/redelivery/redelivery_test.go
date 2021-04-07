/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redelivery

import (
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	s := NewService("service1", nil, nil)
	require.NotNil(t, s)
	require.Equalf(t, DefaultConfig(), s.Config, "should have used default config if nil config was passed as an arg")
}

func TestService(t *testing.T) {
	notifyChan := make(chan *message.Message)

	cfg := &Config{
		MaxRetries:     2,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Second,
		BackoffFactor:  1.5,
		MaxMessages:    20,
	}

	s := NewService("service1", cfg, notifyChan)
	require.NotNil(t, s)

	s.Start()

	payload := []byte("payload")

	t.Run("Success", func(t *testing.T) {
		msg := message.NewMessage(watermill.NewUUID(), payload)

		now := time.Now()

		deliveryTime, err := s.Add(msg)
		require.NoError(t, err)
		require.True(t, deliveryTime.After(now.Add(cfg.InitialBackoff)))

		var undeliverableMsg *message.Message

		select {
		case m := <-notifyChan:
			undeliverableMsg = m
		case <-time.After(100 * time.Millisecond):
		}

		require.NotNil(t, undeliverableMsg)
	})

	t.Run("Invalid metadata -> Error", func(t *testing.T) {
		msg := message.NewMessage(watermill.NewUUID(), payload)
		msg.Metadata[metadataRedeliveryAttempts] = "invalid"

		_, err := s.Add(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "convert redelivery attempts metadata to number")
	})

	t.Run("Max attempts reached -> Error", func(t *testing.T) {
		msg := message.NewMessage(watermill.NewUUID(), payload)
		msg.Metadata[metadataRedeliveryAttempts] = "2"

		_, err := s.Add(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to redeliver message after 2 redelivery attempts")
	})

	// Add a message and immediately shut down to ensure we don't panic.
	_, err := s.Add(message.NewMessage(watermill.NewUUID(), payload))
	require.NoError(t, err)

	s.Stop()
}

func TestBackoff(t *testing.T) {
	cfg := &Config{
		MaxRetries:     2,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Second,
		BackoffFactor:  1.5,
		MaxMessages:    20,
	}

	s := NewService("service1", cfg, nil)
	require.NotNil(t, s)

	require.Equal(t, cfg.InitialBackoff, s.backoff(0))
	require.True(t, s.backoff(1) > cfg.InitialBackoff)
	require.Equal(t, cfg.MaxBackoff, s.backoff(10))
}
