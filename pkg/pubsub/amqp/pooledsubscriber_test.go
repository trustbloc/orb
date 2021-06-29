/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/mocks"
)

func TestPooledSubscriber(t *testing.T) {
	const topic = "pooled"

	t.Run("Subscriber -> error", func(t *testing.T) {
		s := &mocks.PubSub{}

		errExpected := errors.New("injected subscriber error")

		s.SubscribeReturns(nil, errExpected)

		_, err := newPooledSubscriber(context.Background(), 10, s, topic)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Start/Stop", func(t *testing.T) {
		msgChan := make(chan *message.Message)

		pubSub := &mocks.PubSub{}
		pubSub.SubscribeReturns(msgChan, nil)

		ps, err := newPooledSubscriber(context.Background(), 10, pubSub, topic)
		require.NoError(t, err)
		require.NotNil(t, ps)

		ps.start()

		time.Sleep(50 * time.Millisecond)

		ps.stop()
	})
}
