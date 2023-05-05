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
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/pubsub"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

type (
	anchorProcessor func(context.Context, *linkset.Linkset) error
)

// Subscriber implements a subscriber that processes witnessed verifiable credentials from a message queue.
type Subscriber struct {
	*lifecycle.Lifecycle

	vcChan        <-chan *message.Message
	processAnchor anchorProcessor
	jsonUnmarshal func(data []byte, v interface{}) error
}

// NewSubscriber returns a new verifiable credential subscriber.
func NewSubscriber(pubSub pubSub, processor anchorProcessor, subscriberPoolSize int) (*Subscriber, error) {
	h := &Subscriber{
		processAnchor: processor,
		jsonUnmarshal: json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New("anchoreventsubscriber", lifecycle.WithStart(h.start))

	logger.Debug("Subscribing to topic", log.WithTopic(anchorTopic))

	vcChan, err := pubSub.SubscribeWithOpts(context.Background(), anchorTopic, spi.WithPool(subscriberPoolSize))
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
	logger.Debug("Starting message listener")

	for msg := range h.vcChan {
		logger.Debug("Got new anchor event message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

		go h.handleAnchorMessage(msg)
	}

	logger.Debug("Listener stopped.")
}

func (h *Subscriber) handleAnchorMessage(msg *message.Message) {
	logger.Debug("Handling message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

	anchorLinkset := &linkset.Linkset{}

	err := h.jsonUnmarshal(msg.Payload, &anchorLinkset)
	if err != nil {
		logger.Error("Error parsing anchor Linkset", logfields.WithMessageID(msg.UUID), log.WithError(err))

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	ctx := pubsub.ContextFromMessage(msg)

	err = h.processAnchor(ctx, anchorLinkset)

	switch {
	case err == nil:
		logger.Debugc(ctx, "Acking anchor Linkset message", logfields.WithMessageID(msg.UUID))

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warnc(ctx, "Nacking anchor Linkset message since it could not be processed due "+
			"to a transient error", logfields.WithMessageID(msg.UUID), log.WithError(err))

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warnc(ctx, "Acking anchor link message since it could not be processed due "+
			"to a persistent error", logfields.WithMessageID(msg.UUID), log.WithError(err))

		msg.Ack()
	}
}
