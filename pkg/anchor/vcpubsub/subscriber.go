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
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

type (
	vcProcessor func(vc *verifiable.Credential) error
)

type documentLoader interface {
	LoadDocument(u string) (*ld.RemoteDocument, error)
}

// Subscriber implements a subscriber that processes witnessed verifiable credentials from a message queue.
type Subscriber struct {
	*lifecycle.Lifecycle

	vcChan                      <-chan *message.Message
	processVerifiableCredential vcProcessor
	documentLoader              documentLoader
	jsonUnmarshal               func(data []byte, v interface{}) error
}

// NewSubscriber returns a new verifiable credential subscriber.
func NewSubscriber(pubSub pubSub, vcProcessor vcProcessor, documentLoader documentLoader) (*Subscriber, error) {
	h := &Subscriber{
		processVerifiableCredential: vcProcessor,
		documentLoader:              documentLoader,
		jsonUnmarshal:               json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New("vcsubscriber",
		lifecycle.WithStart(h.start),
	)

	logger.Debugf("Subscribing to topic [%s]", vcTopic)

	vcChan, err := pubSub.Subscribe(context.Background(), vcTopic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", vcTopic, err)
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
		logger.Debugf("Got new verifiable credential message: %s: %s", msg.UUID, msg.Payload)

		h.handleVerifiableCredentialMessage(msg)
	}

	logger.Debugf("Listener stopped.")
}

func (h *Subscriber) handleVerifiableCredentialMessage(msg *message.Message) {
	logger.Debugf("Handling message [%s]: %s", msg.UUID, msg.Payload)

	vc, err := verifiable.ParseCredential(msg.Payload,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.documentLoader),
	)
	if err != nil {
		logger.Errorf("Error parsing verifiable credential [%s]: %s", msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	err = h.processVerifiableCredential(vc)

	switch {
	case err == nil:
		logger.Debugf("Acking verifiable credential message. MsgID [%s], VC ID [%s]", msg.UUID, vc.ID)

		msg.Ack()
	case errors.IsTransient(err):
		// The message should be redelivered to (potentially) another server instance.
		logger.Warnf("Nacking verifiable credential message since it could not be delivered due "+
			"to a transient error. MsgID [%s], VC ID [%s]: %s", msg.UUID, vc.ID, err)

		msg.Nack()
	default:
		// A persistent message should not be retried.
		logger.Warnf("Acking verifiable credential message since it could not be delivered due "+
			"to a persistent error. MsgID [%s], VC ID [%s]: %s", msg.UUID, vc.ID, err)

		msg.Ack()
	}
}
