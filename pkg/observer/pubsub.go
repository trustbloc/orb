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

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	anchorTopic = "anchor"
	didTopic    = "did"
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
func NewPubSub(pubSub pubSub, anchorProcessor anchorProcessor, didProcessor didProcessor) (*PubSub, error) {
	h := &PubSub{
		publisher:      pubSub,
		processAnchors: anchorProcessor,
		processDID:     didProcessor,
		jsonUnmarshal:  json.Unmarshal,
		jsonMarshal:    json.Marshal,
	}

	h.Lifecycle = lifecycle.New("observer",
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	anchorCredChan, err := pubSub.Subscribe(context.Background(), anchorTopic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", anchorTopic, err)
	}

	h.anchorCredChan = anchorCredChan

	didChan, err := pubSub.Subscribe(context.Background(), didTopic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", didTopic, err)
	}

	h.didChan = didChan

	return h, nil
}

// PublishAnchor publishes the anchor to the queue for processing.
func (h *PubSub) PublishAnchor(anchorInfo *anchorinfo.AnchorInfo) error {
	payload, err := h.jsonMarshal(anchorInfo)
	if err != nil {
		return fmt.Errorf("publish anchorInfo: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), payload)

	logger.Debugf("Publishing anchors to topic [%s]: %s", anchorTopic, anchorInfo)

	return h.publisher.Publish(anchorTopic, msg)
}

// PublishDID publishes the DID to the queue for processing.
func (h *PubSub) PublishDID(did string) error {
	payload, err := h.jsonMarshal(did)
	if err != nil {
		return fmt.Errorf("publish DID: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), payload)

	logger.Debugf("Publishing DIDs to topic [%s]: %s", didTopic, did)

	return h.publisher.Publish(didTopic, msg)
}

func (h *PubSub) start() {
	// Start the message listener
	go h.listen()
}

func (h *PubSub) stop() {
	if err := h.publisher.Close(); err != nil {
		logger.Warnf("Error closing publisher: %s", err)

		return
	}

	logger.Debugf("Closed publisher")
}

func (h *PubSub) listen() {
	logger.Debugf("Starting message listener")

	for {
		select {
		case msg, ok := <-h.anchorCredChan:
			if !ok {
				logger.Debugf("Message listener stopped")

				return
			}

			logger.Debugf("Got new anchor credential message: %s: %s", msg.UUID, msg.Payload)

			h.handleAnchorCredentialMessage(msg)

		case msg, ok := <-h.didChan:
			if !ok {
				logger.Debugf("Message listener stopped")

				return
			}

			logger.Debugf("Got new DID message: %s: %s", msg.UUID, msg.Payload)

			h.handleDIDMessage(msg)
		}
	}
}

func (h *PubSub) handleAnchorCredentialMessage(msg *message.Message) {
	logger.Debugf("Handling message [%s]: %s", msg.UUID, msg.Payload)

	anchorInfo := &anchorinfo.AnchorInfo{}

	err := h.jsonUnmarshal(msg.Payload, anchorInfo)
	if err != nil {
		logger.Errorf("Error unmarshalling anchor [%s]: %s", msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	h.ackNackMessage(msg, h.processAnchors(anchorInfo))
}

func (h *PubSub) handleDIDMessage(msg *message.Message) {
	logger.Debugf("Handling message [%s]: %s", msg.UUID, msg.Payload)

	var did string

	err := h.jsonUnmarshal(msg.Payload, &did)
	if err != nil {
		logger.Errorf("Error unmarshalling message [%s]: %s", msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	h.ackNackMessage(msg, h.processDID(did))
}

func (h *PubSub) ackNackMessage(msg *message.Message, err error) {
	if errors.IsTransient(err) {
		// The message should be redelivered to (potentially) another server instance.
		msg.Nack()
	} else {
		// A persistent message should not be retried.
		msg.Ack()
	}
}
