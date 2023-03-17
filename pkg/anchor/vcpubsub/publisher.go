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
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/pubsub"
)

var logger = log.New("anchor")

const anchorTopic = "orb.anchor_linkset"

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
func (h *Publisher) Publish(ctx context.Context, anchorLinkset *linkset.Linkset) error {
	payload, err := h.jsonMarshal(anchorLinkset)
	if err != nil {
		return fmt.Errorf("marshal anchor link: %w", err)
	}

	logger.Debugc(ctx, "Publishing anchor linkset", log.WithTopic(anchorTopic), logfields.WithData(payload))

	err = h.pubSub.Publish(anchorTopic, pubsub.NewMessage(ctx, payload))
	if err != nil {
		return errors.NewTransient(err)
	}

	return nil
}
