/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/mocks"
)

func TestPooledSubscriber(t *testing.T) {
	t.Run("Subscriber -> error", func(t *testing.T) {
		const (
			n     = 100
			topic = "pooled"
		)

		p := New(Config{
			URI: "amqp://guest:guest@localhost:5672/",
		})
		require.NotNil(t, p)
		defer func() {
			require.NoError(t, p.Close())
		}()

		s := &mocks.PubSub{}

		errExpected := errors.New("injected subscriber error")

		s.SubscribeReturns(nil, errExpected)

		_, err := newPooledSubscriber(context.Background(), 10, s, topic)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}
