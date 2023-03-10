/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.uber.org/zap"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

const (
	anchorTopic = "orb.anchor"
	didTopic    = "orb.did"
)

type (
	anchorProcessor func(anchor *anchorinfo.AnchorInfo) error
	didProcessor    func(did string) error
)

type messagePublisher interface {
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// PubSub implements a publisher/subscriber that publishes anchors and DIDs to a queue and processes
// anchors and DIDs published to the queue.
type PubSub struct {
	*lifecycle.Lifecycle

	publisher      messagePublisher
	anchorCredChan <-chan *message.Message
	didChan        <-chan *message.Message
	processAnchors anchorProcessor
	processDID     didProcessor
	jsonUnmarshal  func(data []byte, v interface{}) error
	jsonMarshal    func(v interface{}) ([]byte, error)
}

// NewPubSub returns a new publisher/subscriber.
func NewPubSub(pubSub pubSub, anchorProcessor anchorProcessor, didProcessor didProcessor,
	poolSize int) (*PubSub, error) {
	h := &PubSub{
		publisher:      pubSub,
		processAnchors: anchorProcessor,
		processDID:     didProcessor,
		jsonUnmarshal:  json.Unmarshal,
		jsonMarshal:    json.Marshal,
	}

	h.Lifecycle = lifecycle.New("observer-pubsub",
		lifecycle.WithStart(h.start),
	)

	logger.Info("Subscribing to topic", log.WithTopic(anchorTopic))

	anchorCredChan, err := pubSub.SubscribeWithOpts(context.Background(), anchorTopic, spi.WithPool(poolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", anchorTopic, err)
	}

	h.anchorCredChan = anchorCredChan

	logger.Info("Subscribing to topic", log.WithTopic(didTopic))

	didChan, err := pubSub.SubscribeWithOpts(context.Background(), didTopic, spi.WithPool(poolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", didTopic, err)
	}

	h.didChan = didChan

	return h, nil
}

// PublishAnchor publishes the anchor to the queue for processing.
func (h *PubSub) PublishAnchor(anchorInfo *anchorinfo.AnchorInfo) error {
	if h.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	payload, err := h.jsonMarshal(anchorInfo)
	if err != nil {
		return fmt.Errorf("publish anchorInfo: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), payload)

	logger.Debug("Publishing anchors message to queue", logfields.WithMessageID(msg.UUID),
		log.WithTopic(anchorTopic), logfields.WithData(msg.Payload))

	err = h.publisher.Publish(anchorTopic, msg)
	if err != nil {
		logger.Warn("Error publishing anchors message to queue", log.WithTopic(anchorTopic),
			logfields.WithData(msg.Payload), log.WithError(err))

		return errors.NewTransient(err)
	}

	logger.Debug("Successfully published anchors message to queue", logfields.WithMessageID(msg.UUID),
		log.WithTopic(anchorTopic), logfields.WithData(msg.Payload))

	return nil
}

// PublishDID publishes the DID to the queue for processing.
func (h *PubSub) PublishDID(did string) error {
	if h.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	payload, err := h.jsonMarshal(did)
	if err != nil {
		return fmt.Errorf("publish DID: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), payload)

	logger.Debug("Publishing DIDs to queue", log.WithTopic(didTopic), logfields.WithDID(did))

	return h.publisher.Publish(didTopic, msg)
}

func (h *PubSub) start() {
	// Start the message listener
	go h.listen()
}

func (h *PubSub) listen() {
	logger.Debug("Starting message listener")

	for {
		select {
		case msg, ok := <-h.anchorCredChan:
			if !ok {
				logger.Debug("Message listener stopped")

				return
			}

			logger.Debug("Got new anchor credential message", logfields.WithMessageID(msg.UUID),
				logfields.WithMetadata(msg.Metadata), logfields.WithData(msg.Payload))

			h.handleAnchorCredentialMessage(msg)

		case msg, ok := <-h.didChan:
			if !ok {
				logger.Debug("Message listener stopped")

				return
			}

			logger.Debug("Got new DID message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

			h.handleDIDMessage(msg)
		}
	}
}

func (h *PubSub) handleAnchorCredentialMessage(msg *message.Message) {
	logger.Debug("Handling message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

	anchorInfo := &anchorinfo.AnchorInfo{}

	err := h.jsonUnmarshal(msg.Payload, anchorInfo)
	if err != nil {
		logger.Error("Error unmarshalling anchor", logfields.WithMessageID(msg.UUID), log.WithError(err))

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	h.ackNackMessage(msg, h.processAnchors(anchorInfo), logfields.WithAnchorEventURIString(anchorInfo.Hashlink),
		logfields.WithAttributedTo(anchorInfo.AttributedTo), logfields.WithLocalHashlink(anchorInfo.LocalHashlink))
}

func (h *PubSub) handleDIDMessage(msg *message.Message) {
	logger.Debug("Handling message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

	var did string

	err := h.jsonUnmarshal(msg.Payload, &did)
	if err != nil {
		logger.Error("Error unmarshalling message", logfields.WithMessageID(msg.UUID), log.WithError(err))

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	h.ackNackMessage(msg, h.processDID(did), logfields.WithDID(did))
}

func (h *PubSub) ackNackMessage(msg *message.Message, err error, logFields ...zap.Field) {
	switch {
	case err == nil:
		logger.Debug("Acking message", append(logFields, logfields.WithMessageID(msg.UUID))...)

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warn("Nacking message since it could not be delivered due to a transient error",
			append(logFields, logfields.WithMessageID(msg.UUID), log.WithError(err))...)

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warn("Acking message since it could not be delivered due to a persistent error",
			append(logFields, logfields.WithMessageID(msg.UUID))...)

		msg.Ack()
	}
}
