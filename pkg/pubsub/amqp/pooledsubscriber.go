/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
)

// pooledSubscriber manages a pool of subscriptions. Each subscription listens on a topic and forwards
// the message to a Go channel that is consumed by the subscriber.
type pooledSubscriber struct {
	topic       string
	subscribers []*poolSubscriber
	msgChan     chan *message.Message
}

func newPooledSubscriber(ctx context.Context, size uint, subscriber subscriber,
	topic string) (*pooledSubscriber, error) {
	p := &pooledSubscriber{
		topic:   topic,
		msgChan: make(chan *message.Message, size),
	}

	for i := uint(0); i < size; i++ {
		ps, err := newPoolSubscriber(ctx, i, topic, subscriber, p.msgChan)
		if err != nil {
			return nil, fmt.Errorf("create pool subscriber: %w", err)
		}

		p.subscribers = append(p.subscribers, ps)
	}

	return p, nil
}

func (s *pooledSubscriber) start() {
	logger.Infof("[%s] Starting pooled subscriber with %d listeners", s.topic, len(s.subscribers))

	for _, subscriber := range s.subscribers {
		go subscriber.listen()
	}
}

func (s *pooledSubscriber) stop() {
	logger.Infof("[%s] Closing pooled subscriber", s.topic)

	for _, s := range s.subscribers {
		s.stop()
	}

	close(s.msgChan)
}

type poolSubscriber struct {
	n           uint
	topic       string
	msgChan     <-chan *message.Message
	poolMsgChan chan<- *message.Message
	stopChan    chan struct{}
	stoppedChan chan struct{}
}

func newPoolSubscriber(ctx context.Context, n uint, topic string, s subscriber,
	poolMsgChan chan<- *message.Message) (*poolSubscriber, error) {
	logger.Debugf("[%s-%d] Subscribing...", topic, n)

	msgChan, err := s.Subscribe(ctx, topic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	return &poolSubscriber{
		n:           n,
		topic:       topic,
		msgChan:     msgChan,
		poolMsgChan: poolMsgChan,
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}, nil
}

func (s *poolSubscriber) listen() {
	logger.Debugf("[%s-%d] Pool subscriber listener started", s.topic, s.n)

	for {
		select {
		case msg, ok := <-s.msgChan:
			if !ok {
				logger.Debugf("[%s-%d] Message channel was closed.", s.topic, s.n)

				s.stoppedChan <- struct{}{}

				return
			}

			logger.Debugf("[%s-%d] Pool subscriber got message [%s]", s.topic, s.n, msg.UUID)

			s.poolMsgChan <- msg
		case <-s.stopChan:
			logger.Debugf("[%s-%d] Listener was requested to stop", s.topic, s.n)

			s.stoppedChan <- struct{}{}

			return
		}
	}
}

func (s *poolSubscriber) stop() {
	logger.Debugf("[%s-%d] Stopping Pool subscriber listener...", s.topic, s.n)

	close(s.stopChan)

	logger.Debugf("[%s-%d] ... waiting for pool subscriber listener to stop...", s.topic, s.n)

	<-s.stoppedChan

	logger.Debugf("[%s-%d] ... pool subscriber stopped", s.topic, s.n)
}
