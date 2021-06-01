/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

const (
	dockerImage = "rabbitmq"
	dockerTag   = "3.8.16"
)

func TestAMQP(t *testing.T) {
	const topic = "some-topic"

	t.Run("Success", func(t *testing.T) {
		p := New("", Config{URI: "amqp://guest:guest@localhost:5672/"})
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
		require.True(t, errors.Is(err, spi.ErrNotStarted))
		require.True(t, errors.Is(p.Publish(topic, msg), spi.ErrNotStarted))
	})

	t.Run("Connection failure", func(t *testing.T) {
		require.Panics(t, func() {
			p := New("", Config{URI: "amqp://guest:guest@localhost:9999/", MaxConnectRetries: 3})
			require.NotNil(t, p)
		})
	})
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
		logger.Errorf(`Failed to start RabbitMQ Docker image.`)

		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(resource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	code = m.Run()
}
