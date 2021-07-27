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
)

// pooledSubscriber manages a pool of subscriptions. Each subscription listens on a topic and forwards
// the message to a Go channel that is consumed by the subscriber.
type pooledSubscriber struct {
	topic       string
	msgChan     chan *message.Message
	subscribers []reflect.SelectCase
}

func newPooledSubscriber(ctx context.Context, size uint, subscriber subscriber,
	topic string) (*pooledSubscriber, error) {
	p := &pooledSubscriber{
		topic:       topic,
		msgChan:     make(chan *message.Message, size),
		subscribers: make([]reflect.SelectCase, size),
	}

	for i := uint(0); i < size; i++ {
		logger.Debugf("[%s-%d] Subscribing...", topic, i)

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
		logger.Infof("[%s] Started pooled subscriber with %d listeners", s.topic, len(s.subscribers))

		for {
			i, value, ok := reflect.Select(s.subscribers)

			if !ok {
				logger.Infof("[%s] Message channel [%d] was closed. Exiting pooled subscriber.", s.topic, i)

				return
			}

			msg := value.Interface().(*message.Message) //nolint:errcheck,forcetypeassert

			logger.Debugf("[%s-%d] Pool subscriber got message [%s]", s.topic, i, msg.UUID)

			s.msgChan <- msg
		}
	}()
}

func (s *pooledSubscriber) stop() {
	logger.Infof("[%s] Closing pooled subscriber", s.topic)

	close(s.msgChan)
}
