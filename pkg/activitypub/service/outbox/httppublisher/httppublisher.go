/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httppublisher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
)

var logger = log.New("activitypub_service")

// MetadataSendTo is the metadata key for the destination URL.
const MetadataSendTo = "send_to"

// Publisher is an implementation of a Watermill Publisher that publishes messages over HTTP.
type Publisher struct {
	*lifecycle.Lifecycle

	ServiceName    string
	client         *http.Client
	jsonMarshal    func(v interface{}) ([]byte, error)
	newRequestFunc func(string, *message.Message) (*http.Request, error)
}

// New creates a new HTTP Publisher.
func New(serviceName string, client *http.Client) *Publisher {
	p := &Publisher{
		ServiceName: serviceName,
		Lifecycle:   lifecycle.New(serviceName),
		client:      client,
		jsonMarshal: json.Marshal,
	}

	p.newRequestFunc = p.newRequest

	// The service must be started immediately.
	p.Start()

	return p
}

// Publish publishes the messages over HTTP to the destination specified in the
// messages 'send-to' metadata.
func (p *Publisher) Publish(topic string, messages ...*message.Message) error {
	for _, msg := range messages {
		if err := p.publish(topic, msg); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the publisher.
func (p *Publisher) Close() error {
	p.Stop()

	return nil
}

func (p *Publisher) publish(topic string, msg *message.Message) error {
	req, err := p.newRequestFunc(topic, msg)
	if err != nil {
		return fmt.Errorf("marshal message %s: %w", msg.UUID, err)
	}

	logger.Debugf("[%s] Sending message [%s] to [%s] ", p.ServiceName, msg.UUID, req.URL)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("send message [%s]: %w", msg.UUID, err)
	}

	if err := resp.Body.Close(); err != nil {
		logger.Warnf("[%s] Error closing response body: %s", p.ServiceName, err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		logger.Debugf("[%s] Error code %d received in response from [%s] for message [%s]",
			p.ServiceName, resp.StatusCode, req.URL, msg.UUID)

		return fmt.Errorf("server responded with error %d - %s", resp.StatusCode, resp.Status)
	}

	logger.Debugf("[%s] Message successfully sent [%s] to [%s] ", p.ServiceName, msg.UUID, req.URL)

	return nil
}

func (p *Publisher) newRequest(_ string, msg *message.Message) (*http.Request, error) {
	toURL, ok := msg.Metadata[MetadataSendTo]
	if !ok {
		return nil, fmt.Errorf("metadata [%s] not found in message", MetadataSendTo)
	}

	req, err := http.NewRequest(http.MethodPost, toURL, bytes.NewBuffer(msg.Payload))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}

	req.Header.Set(wmhttp.HeaderUUID, msg.UUID)

	metadataBytes, err := p.jsonMarshal(msg.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata to JSON: %w", err)
	}

	req.Header.Set(wmhttp.HeaderMetadata, string(metadataBytes))

	return req, nil
}
