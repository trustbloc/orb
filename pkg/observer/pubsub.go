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

	logger.Infof("Subscribing to topic [%s]", anchorTopic)

	anchorCredChan, err := pubSub.SubscribeWithOpts(context.Background(), anchorTopic, spi.WithPool(poolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", anchorTopic, err)
	}

	h.anchorCredChan = anchorCredChan

	logger.Infof("Subscribing to topic [%s]", didTopic)

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

	logger.Debugf("Publishing anchors message [%s] to topic [%s]: %s", msg.UUID, anchorTopic, msg.Payload)

	err = h.publisher.Publish(anchorTopic, msg)
	if err != nil {
		logger.Warnf("Error publishing anchors message [%s] to topic [%s]: %s", msg.UUID, anchorTopic, err)

		return errors.NewTransient(err)
	}

	logger.Debugf("Successfully published anchors message [%s] to topic [%s]: %s",
		msg.UUID, anchorTopic, msg.Payload)

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

	logger.Debugf("Publishing DIDs to topic [%s]: %s", didTopic, did)

	return h.publisher.Publish(didTopic, msg)
}

func (h *PubSub) start() {
	// Start the message listener
	go h.listen()
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

			logger.Debugf("Got new anchor credential message [%s], Metadata: %s, Payload %s",
				msg.UUID, msg.Metadata, msg.Payload)

			h.handleAnchorCredentialMessage(msg)

		case msg, ok := <-h.didChan:
			if !ok {
				logger.Debugf("Message listener stopped")

				return
			}

			logger.Debugf("Got new DID message [%s]: %s", msg.UUID, msg.Payload)

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

	h.ackNackMessage(msg, newAnchorInfo(anchorInfo), h.processAnchors(anchorInfo))
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

	h.ackNackMessage(msg, newDIDInfo(did), h.processDID(did))
}

func (h *PubSub) ackNackMessage(msg *message.Message, info fmt.Stringer, err error) {
	switch {
	case err == nil:
		logger.Infof("Acking message [%s] for %s", msg.UUID, info)

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warnf("Nacking message [%s] for %s since it could not be delivered due to a transient error: %s",
			msg.UUID, info, err)

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warnf("Acking message [%s] for DID [%s] since it could not be delivered due to a persistent error: %s",
			msg.UUID, info, err)

		msg.Ack()
	}
}

type anchorInfo struct {
	hashLink      string
	attributedTo  string
	localHashlink string
}

func newAnchorInfo(info *anchorinfo.AnchorInfo) *anchorInfo {
	return &anchorInfo{
		hashLink:      info.Hashlink,
		attributedTo:  info.AttributedTo,
		localHashlink: info.LocalHashlink,
	}
}

func (info *anchorInfo) String() string {
	str := fmt.Sprintf("anchor - HL [%s]", info.hashLink)
	if info.attributedTo == "" {
		return str
	}

	return fmt.Sprintf("%s, LocalHL [%s], attributedTo [%s]", str, info.localHashlink, info.attributedTo)
}

type didInfo struct {
	did string
}

func newDIDInfo(did string) *didInfo {
	return &didInfo{did: did}
}

func (m *didInfo) String() string {
	return fmt.Sprintf("DID [%s]", m.did)
}
