/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/trustbloc/orb/internal/pkg/log"
)

// pooledSubscriber manages a pool of subscriptions. Each subscription listens on a topic and forwards
// the message to a Go channel that is consumed by the subscriber.
type pooledSubscriber struct {
	topic       string
	msgChan     chan *message.Message
	subscribers []reflect.SelectCase
	logger      *log.Log
}

func newPooledSubscriber(ctx context.Context, size int, subscriber subscriber,
	topic string) (*pooledSubscriber, error) {
	l := log.New(loggerModule, log.WithFields(log.WithTopic(topic)))

	p := &pooledSubscriber{
		topic:       topic,
		msgChan:     make(chan *message.Message, size),
		subscribers: make([]reflect.SelectCase, size),
		logger:      l,
	}

	for i := 0; i < size; i++ {
		l.Debug("Subscribing to topic...", log.WithIndex(i))

		msgChan, err := subscriber.Subscribe(ctx, topic)
		if err != nil {
			return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
		}

		p.subscribers[i].Dir = reflect.SelectRecv
		p.subscribers[i].Chan = reflect.ValueOf(msgChan)
	}

	return p, nil
}

func (s *pooledSubscriber) start() {
	go func() {
		s.logger.Info("Started pooled subscriber", log.WithSize(len(s.subscribers)))

		for {
			i, value, ok := reflect.Select(s.subscribers)

			if !ok {
				logger.Info("Message channel was closed. Exiting pooled subscriber.", log.WithIndex(i))

				return
			}

			msg := value.Interface().(*message.Message) //nolint:errcheck,forcetypeassert

			logger.Debug("Pool subscriber got message", log.WithIndex(i), log.WithMessageID(msg.UUID))

			s.msgChan <- msg
		}
	}()
}

func (s *pooledSubscriber) stop() {
	logger.Info("Closing pooled subscriber")

	close(s.msgChan)
}
