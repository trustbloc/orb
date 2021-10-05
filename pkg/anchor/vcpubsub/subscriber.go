/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcpubsub

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

type (
	anchorEventProcessor func(*vocab.AnchorEventType) error
)

// Subscriber implements a subscriber that processes witnessed verifiable credentials from a message queue.
type Subscriber struct {
	*lifecycle.Lifecycle

	vcChan             <-chan *message.Message
	processAnchorEvent anchorEventProcessor
	jsonUnmarshal      func(data []byte, v interface{}) error
}

// NewSubscriber returns a new verifiable credential subscriber.
func NewSubscriber(pubSub pubSub, processor anchorEventProcessor) (*Subscriber, error) {
	h := &Subscriber{
		processAnchorEvent: processor,
		jsonUnmarshal:      json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New("anchoreventsubscriber",
		lifecycle.WithStart(h.start),
	)

	logger.Debugf("Subscribing to topic [%s]", anchorEventTopic)

	vcChan, err := pubSub.Subscribe(context.Background(), anchorEventTopic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", anchorEventTopic, err)
	}

	h.vcChan = vcChan

	return h, nil
}

func (h *Subscriber) start() {
	// Start the message listener
	go h.listen()
}

func (h *Subscriber) listen() {
	logger.Debugf("Starting message listener")

	for msg := range h.vcChan {
		logger.Debugf("Got new anchor event message: %s: %s", msg.UUID, msg.Payload)

		h.handleAnchorEventMessage(msg)
	}

	logger.Debugf("Listener stopped.")
}

func (h *Subscriber) handleAnchorEventMessage(msg *message.Message) {
	logger.Debugf("Handling message [%s]: %s", msg.UUID, msg.Payload)

	anchorEvent := &vocab.AnchorEventType{}

	err := h.jsonUnmarshal(msg.Payload, &anchorEvent)
	if err != nil {
		logger.Errorf("Error parsing anchor event [%s]: %s", msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	err = h.processAnchorEvent(anchorEvent)

	switch {
	case err == nil:
		logger.Debugf("Acking anchor event message. MsgID [%s], VC ID [%s]", msg.UUID, anchorEvent.ID)

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warnf("Nacking anchor event message since it could not be processed due "+
			"to a transient error. MsgID [%s], VC ID [%s]: %s", msg.UUID, anchorEvent.ID, err)

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warnf("Acking anchor event message since it could not be processed due "+
			"to a persistent error. MsgID [%s], VC ID [%s]: %s", msg.UUID, anchorEvent.ID, err)

		msg.Ack()
	}
}
