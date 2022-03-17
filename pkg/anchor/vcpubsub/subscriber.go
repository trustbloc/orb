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

	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/linkset"
)

type (
	anchorProcessor func(*linkset.Linkset) error
)

// Subscriber implements a subscriber that processes witnessed verifiable credentials from a message queue.
type Subscriber struct {
	*lifecycle.Lifecycle

	vcChan        <-chan *message.Message
	processAnchor anchorProcessor
	jsonUnmarshal func(data []byte, v interface{}) error
}

// NewSubscriber returns a new verifiable credential subscriber.
func NewSubscriber(pubSub pubSub, processor anchorProcessor) (*Subscriber, error) {
	h := &Subscriber{
		processAnchor: processor,
		jsonUnmarshal: json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New("anchoreventsubscriber",
		lifecycle.WithStart(h.start),
	)

	logger.Debugf("Subscribing to topic [%s]", anchorTopic)

	vcChan, err := pubSub.Subscribe(context.Background(), anchorTopic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", anchorTopic, err)
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

		h.handleAnchorMessage(msg)
	}

	logger.Debugf("Listener stopped.")
}

func (h *Subscriber) handleAnchorMessage(msg *message.Message) {
	logger.Debugf("Handling message [%s]: %s", msg.UUID, msg.Payload)

	anchorLinkset := &linkset.Linkset{}

	err := h.jsonUnmarshal(msg.Payload, &anchorLinkset)
	if err != nil {
		logger.Errorf("Error parsing anchor Linkset [%s]: %s", msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	err = h.processAnchor(anchorLinkset)

	switch {
	case err == nil:
		logger.Debugf("Acking anchor Linkset message. MsgID [%s]", msg.UUID)

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warnf("Nacking anchor Linkset message since it could not be processed due "+
			"to a transient error. MsgID [%s]: %s", msg.UUID, err)

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warnf("Acking anchor link message since it could not be processed due "+
			"to a persistent error. MsgID [%s]: %s", msg.UUID, err)

		msg.Ack()
	}
}
