/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcpubsub

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("anchor")

const anchorEventTopic = "anchor-event"

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

// Publisher implements a publisher that publishes witnessed verifiable credentials to a message queue.
type Publisher struct {
	pubSub      pubSub
	jsonMarshal func(v interface{}) ([]byte, error)
}

// NewPublisher returns a new verifiable credential publisher.
func NewPublisher(pubSub pubSub) *Publisher {
	return &Publisher{
		pubSub:      pubSub,
		jsonMarshal: json.Marshal,
	}
}

// Publish publishes a verifiable credential to a message queue for processing.
func (h *Publisher) Publish(anchorEvent *vocab.AnchorEventType) error {
	payload, err := h.jsonMarshal(anchorEvent)
	if err != nil {
		return fmt.Errorf("publish anchor event: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), payload)

	logger.Debugf("Publishing anchor event to topic [%s]: %s", anchorEventTopic, anchorEvent)

	err = h.pubSub.Publish(anchorEventTopic, msg)
	if err != nil {
		return errors.NewTransient(err)
	}

	return nil
}
