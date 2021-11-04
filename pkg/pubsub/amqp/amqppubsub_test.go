/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-amqp/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

const (
	dockerImage = "rabbitmq"
	dockerTag   = "3-management-alpine"
)

func TestAMQP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		const topic = "some-topic"

		p := New(Config{URI: "amqp://guest:guest@localhost:5672/"})
		require.NotNil(t, p)

		msgChan, err := p.Subscribe(context.Background(), topic)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), []byte("some payload"))
		require.NoError(t, p.Publish(topic, msg))

		select {
		case m := <-msgChan:
			require.Equal(t, msg.UUID, m.UUID)
		case <-time.After(200 * time.Millisecond):
			t.Fatal("timed out waiting for message")
		}

		require.NoError(t, p.Close())

		_, err = p.Subscribe(context.Background(), topic)
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
		require.True(t, errors.Is(p.Publish(topic, msg), lifecycle.ErrNotStarted))
	})

	t.Run("Connection failure", func(t *testing.T) {
		require.Panics(t, func() {
			p := New(Config{URI: "amqp://guest:guest@localhost:9999/", MaxConnectRetries: 3})
			require.NotNil(t, p)
		})
	})

	t.Run("Pooled subscriber -> success", func(t *testing.T) {
		const (
			n     = 100
			topic = "pooled"
		)

		publishedMessages := &sync.Map{}
		receivedMessages := &sync.Map{}

		p := New(Config{
			URI:                        "amqp://guest:guest@localhost:5672/",
			MaxConnectionSubscriptions: 5,
		})
		require.NotNil(t, p)
		defer func() {
			require.NoError(t, p.Close())
		}()

		msgChan, err := p.SubscribeWithOpts(context.Background(), topic, spi.WithPool(10))
		require.NoError(t, err)

		var wg sync.WaitGroup
		wg.Add(n)

		go func(msgChan <-chan *message.Message) {
			for m := range msgChan {
				go func(msg *message.Message) {
					// Randomly fail 33% of the messages to test redelivery.
					if rand.Int31n(10) < 3 { //nolint:gosec
						msg.Nack()

						return
					}

					receivedMessages.Store(msg.UUID, msg)

					// Add a delay to simulate processing.
					time.Sleep(100 * time.Millisecond)

					msg.Ack()

					wg.Done()
				}(m)
			}
		}(msgChan)

		for i := 0; i < n; i++ {
			go func() {
				msg := message.NewMessage(watermill.NewUUID(), []byte("some payload"))
				publishedMessages.Store(msg.UUID, msg)

				require.NoError(t, p.Publish(topic, msg))
			}()
		}

		wg.Wait()

		publishedMessages.Range(func(msgID, _ interface{}) bool {
			_, ok := receivedMessages.Load(msgID)
			require.Truef(t, ok, "message not received: %s", msgID)

			return true
		})
	})

	t.Run("Redelivery attempts reached", func(t *testing.T) {
		const topic = "topic_redelivery"

		p := New(Config{
			URI:                        "amqp://guest:guest@localhost:5672/",
			MaxConnectionSubscriptions: 5,
			MaxRedeliveryAttempts:      5,
			MaxRedeliveryInterval:      200 * time.Millisecond,
		})
		require.NotNil(t, p)
		defer func() {
			require.NoError(t, p.Close())
		}()

		msgChan2, err := p.SubscribeWithOpts(context.Background(), topic)
		require.NoError(t, err)

		var attempts uint32

		go func(msgChan <-chan *message.Message) {
			for m := range msgChan {
				go func(msg *message.Message) {
					// Always fail to test maximum redelivery attempts.
					msg.Nack()

					atomic.AddUint32(&attempts, 1)
				}(m)
			}
		}(msgChan2)

		go func() {
			require.NoError(t, p.Publish(topic, message.NewMessage(watermill.NewUUID(), []byte("some payload"))))
		}()

		time.Sleep(5 * time.Second)

		require.Equal(t, uint32(6), atomic.LoadUint32(&attempts))
	})
}

func TestAMQP_Error(t *testing.T) {
	const topic = "some-topic"

	t.Run("Subscriber factory error", func(t *testing.T) {
		errExpected := errors.New("injected subscriber subscriberFactory error")

		p := &PubSub{
			Lifecycle: lifecycle.New(""),
			connMgr:   &mockConnectionMgr{},
			subscriberFactory: func(connection) (initializingSubscriber, error) {
				return nil, errExpected
			},
			createPublisher: func(connection) (publisher, error) {
				return &mockPublisher{}, nil
			},
			createWaitPublisher: func(connection) (publisher, error) {
				return &mockPublisher{}, nil
			},
		}

		p.Start()

		require.NoError(t, p.connect(), errExpected.Error())

		_, err := p.Subscribe(context.Background(), "topic")
		require.EqualError(t, err, errExpected.Error())
	})

	t.Run("Publisher factory error", func(t *testing.T) {
		errExpected := errors.New("injected publisher subscriberFactory error")

		p := &PubSub{
			connMgr: &mockConnectionMgr{},
			subscriberFactory: func(connection) (initializingSubscriber, error) {
				return &mockSubscriber{}, nil
			},
			createPublisher: func(connection) (publisher, error) {
				return nil, errExpected
			},
		}

		require.EqualError(t, p.connect(), errExpected.Error())
	})

	t.Run("Subscribe error", func(t *testing.T) {
		errSubscribe := errors.New("injected subscribe error")
		errClose := errors.New("injected close error")

		p := &PubSub{
			Lifecycle:            lifecycle.New("ampq"),
			connMgr:              &mockConnectionMgr{},
			subscriber:           &mockSubscriber{err: errSubscribe, mockClosable: &mockClosable{err: errClose}},
			publisher:            &mockPublisher{mockClosable: &mockClosable{}},
			waitSubscriber:       &mockSubscriber{err: errSubscribe, mockClosable: &mockClosable{err: errClose}},
			waitPublisher:        &mockPublisher{mockClosable: &mockClosable{}},
			redeliverySubscriber: &mockSubscriber{err: errSubscribe, mockClosable: &mockClosable{err: errClose}},
		}

		p.Start()
		defer p.stop()

		_, err := p.Subscribe(context.Background(), topic)
		require.EqualError(t, err, errSubscribe.Error())
	})

	t.Run("Publisher error", func(t *testing.T) {
		errPublish := errors.New("injected publish error")
		errClose := errors.New("injected close error")

		p := &PubSub{
			Lifecycle:            lifecycle.New("ampq"),
			connMgr:              &mockConnectionMgr{},
			subscriber:           &mockSubscriber{mockClosable: &mockClosable{}},
			publisher:            &mockPublisher{err: errPublish, mockClosable: &mockClosable{err: errClose}},
			waitSubscriber:       &mockSubscriber{mockClosable: &mockClosable{}},
			waitPublisher:        &mockPublisher{err: errPublish, mockClosable: &mockClosable{err: errClose}},
			redeliverySubscriber: &mockSubscriber{mockClosable: &mockClosable{}},
		}

		p.Start()
		defer p.stop()

		require.EqualError(t, p.Publish(topic), errPublish.Error())
	})
}

func TestExtractEndpoint(t *testing.T) {
	require.Equal(t, "example.com:5671/mq",
		extractEndpoint("amqps://user:password@example.com:5671/mq"))

	require.Equal(t, "example.com:5671/mq",
		extractEndpoint("amqps://example.com:5671/mq"))

	require.Equal(t, "",
		extractEndpoint("example.com:5671/mq"))
}

func TestPubSub_GetInterval(t *testing.T) {
	p := &PubSub{
		Config: Config{
			RedeliveryMultiplier:      defaultRedeliveryMultiplier,
			RedeliveryInitialInterval: defaultRedeliveryInitialInterval,
			MaxRedeliveryInterval:     defaultMaxRedeliveryInterval,
		},
	}

	require.Equal(t, time.Duration(0), p.getRedeliveryInterval(0))
	require.Equal(t, defaultRedeliveryInitialInterval, p.getRedeliveryInterval(1))
	require.Equal(t, 3*time.Second, p.getRedeliveryInterval(2))
	require.Equal(t, 4500*time.Millisecond, p.getRedeliveryInterval(3))
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	resource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerImage,
		Tag:        dockerTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5672/tcp": {{HostIP: "", HostPort: "5672"}},
		},
	})
	if err != nil {
		logger.Errorf(`Failed to start RabbitMQ Docker image: %s`, err)

		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(resource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	code = m.Run()
}

type mockClosable struct {
	err error
}

func (m *mockClosable) Close() error {
	return m.err
}

type mockSubscriber struct {
	*mockClosable

	err error
}

func (m *mockSubscriber) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	if m.err != nil {
		return nil, m.err
	}

	return nil, nil
}

func (m *mockSubscriber) SubscribeInitialize(string) error {
	return m.err
}

type mockPublisher struct {
	*mockClosable

	err error
}

func (m *mockPublisher) Publish(topic string, messages ...*message.Message) error {
	if m.err != nil {
		return m.err
	}

	return nil
}

type mockConnectionMgr struct {
	err error
}

func (m *mockConnectionMgr) close() error {
	return m.err
}

func (m *mockConnectionMgr) getConnection() (connection, error) {
	if m.err != nil {
		return nil, m.err
	}

	return &mockConnection{}, nil
}

type mockConnection struct{}

func (m *mockConnection) amqpConnection() *amqp.ConnectionWrapper {
	return nil
}

func (m *mockConnection) incrementChannelCount() uint32 {
	return 0
}

func (m *mockConnection) numChannels() uint32 {
	return 0
}
