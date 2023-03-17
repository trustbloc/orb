/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package otelamqp

import (
	"context"
	"errors"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/observability/tracing/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

//go:generate counterfeiter -o ../mocks/pubsub.gen.go --fake-name PubSub . pubSub

func TestPublish(t *testing.T) {
	tp := testutil.InitTracer(t)
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Logf("Error shutting down tracer: %s", err)
		}
	}()

	tracer := tp.Tracer("test-pub-tracer")

	_, span := tracer.Start(context.Background(), "TestConsumer")
	defer span.End()

	ps := &mocks.PubSub{}

	pst := New(ps)

	defer func() {
		require.NoError(t, pst.Close())
	}()

	t.Run("Publish none -> ignore", func(t *testing.T) {
		require.NoError(t, pst.Publish("queue1"))
	})

	t.Run("Publish one -> success", func(t *testing.T) {
		msg := &message.Message{
			UUID:     "xsxsxsx",
			Metadata: make(message.Metadata),
			Payload:  []byte("some data"),
		}

		require.NoError(t, pst.Publish("queue1", msg))
	})

	t.Run("Publish many -> ignore", func(t *testing.T) {
		msg1 := &message.Message{
			UUID:     "xsxsxsx",
			Metadata: make(message.Metadata),
			Payload:  []byte("some data"),
		}

		msg2 := &message.Message{
			UUID:     "fwefwcww",
			Metadata: make(message.Metadata),
			Payload:  []byte("some other data"),
		}

		require.NoError(t, pst.Publish("queue1", msg1, msg2))
	})

	t.Run("PublishWithOpts -> success", func(t *testing.T) {
		msg := &message.Message{
			UUID:     "xsxsxsx",
			Metadata: make(message.Metadata),
			Payload:  []byte("some data"),
		}

		require.NoError(t, pst.PublishWithOpts("queue1", msg))
	})

	t.Run("Publish with error -> success", func(t *testing.T) {
		errExpected := errors.New("injected publish error")

		ps := &mocks.PubSub{}
		ps.PublishReturns(errExpected)

		pst := New(ps)

		defer func() {
			require.NoError(t, pst.Close())
		}()

		msg := &message.Message{
			UUID:     "xsxsxsx",
			Metadata: make(message.Metadata),
			Payload:  []byte("some data"),
		}

		require.EqualError(t, pst.Publish("queue1", msg), errExpected.Error())
	})
}

func TestSubscribe(t *testing.T) {
	tp := testutil.InitTracer(t)
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Logf("Error shutting down tracer: %s", err)
		}
	}()

	tracer := tp.Tracer("test-pub-tracer")

	_, span := tracer.Start(context.Background(), "TestConsumer")
	defer span.End()

	ps := mempubsub.New(mempubsub.DefaultConfig())

	pst := New(ps)

	defer func() {
		require.NoError(t, pst.Close())
	}()

	t.Run("Subscribe -> success", func(t *testing.T) {
		msgChan, err := pst.Subscribe(context.Background(), "queue1")
		require.NoError(t, err)
		require.NotNil(t, msgChan)

		msg := message.NewMessage(uuid.NewString(), []byte("some payload"))

		require.NoError(t, ps.Publish("queue1", msg))

		recevedMsg := <-msgChan

		require.Equal(t, msg.UUID, recevedMsg.UUID)
	})

	t.Run("Subscribe -> error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeReturns(nil, errExpected)

		msgChan, err := New(ps).Subscribe(context.Background(), "queue1")
		require.EqualError(t, err, errExpected.Error())
		require.Nil(t, msgChan)
	})

	t.Run("SubscribeWithOpts -> success", func(t *testing.T) {
		msgChan, err := pst.SubscribeWithOpts(context.Background(), "queue1")
		require.NoError(t, err)
		require.NotNil(t, msgChan)

		msg := message.NewMessage(uuid.NewString(), []byte("some payload"))

		require.NoError(t, ps.Publish("queue1", msg))

		recevedMsg := <-msgChan

		require.Equal(t, msg.UUID, recevedMsg.UUID)
	})

	t.Run("SubscribeWithOpts -> error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeWithOptsReturns(nil, errExpected)

		pst := New(ps)

		msgChan, err := pst.SubscribeWithOpts(context.Background(), "queue1")
		require.EqualError(t, err, errExpected.Error())
		require.Nil(t, msgChan)
	})
}

func TestNewMessageCarrier(t *testing.T) {
	const (
		key1   = "key1"
		key2   = "key2"
		value1 = "value1"
		value2 = "value2"
	)

	msg := message.NewMessage(uuid.NewString(), []byte("some payload"))

	mc := NewMessageCarrier(msg)
	require.NotNil(t, mc)
	require.Empty(t, mc.Keys())

	msg.Metadata.Set(key1, value1)
	mc.Set(key2, value2)

	require.Equal(t, value1, mc.Get(key1))
	require.Equal(t, value2, mc.Get(key2))

	require.Contains(t, mc.Keys(), key1)
	require.Contains(t, mc.Keys(), key2)
}
