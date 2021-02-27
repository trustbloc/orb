/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httppublisher

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
)

var logger = log.New("activitypub_service")

// MetadataSendTo is the metadata key for the destination URL.
const MetadataSendTo = "send_to"

// Config holds the configuration parameters for the HTTP publisher.
type Config struct {
	ServiceName     string
	TLSClientConfig *tls.Config
}

// Publisher is an implementation of a Watermill Publisher that publishes messages over HTTP.
type Publisher struct {
	*Config
	*lifecycle.Lifecycle

	client         *http.Client
	jsonMarshal    func(v interface{}) ([]byte, error)
	newRequestFunc func(string, *message.Message) (*http.Request, error)
}

// New creates a new HTTP Publisher.
func New(cfg *Config) *Publisher {
	p := &Publisher{
		Config:      cfg,
		Lifecycle:   lifecycle.New(cfg.ServiceName),
		client:      resolveHTTPClient(cfg),
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
		return errors.Wrapf(err, "cannot marshal message %s", msg.UUID)
	}

	logger.Debugf("[%s] Sending message [%s] to [%s] ", msg.UUID, req.URL)

	resp, err := p.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "send message [%s] failed", msg.UUID)
	}

	if err := resp.Body.Close(); err != nil {
		logger.Warnf("[%s] Error closing response body: %s", p.ServiceName, err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		logger.Debugf("[%s] Error code %d received in response from [%s] for message [%s]",
			p.ServiceName, resp.StatusCode, req.URL, msg.UUID)

		return errors.Errorf("server responded with error %d - %s", resp.StatusCode, resp.Status)
	}

	logger.Debugf("[%s] Message successfully sent [%s] to [%s] ", msg.UUID, req.URL)

	return nil
}

func (p *Publisher) newRequest(_ string, msg *message.Message) (*http.Request, error) {
	toURL, ok := msg.Metadata[MetadataSendTo]
	if !ok {
		return nil, errors.Errorf("metadata [%s] not found in message", MetadataSendTo)
	}

	req, err := http.NewRequest(http.MethodPost, toURL, bytes.NewBuffer(msg.Payload))
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create HTTP request")
	}

	req.Header.Set(wmhttp.HeaderUUID, msg.UUID)

	metadataBytes, err := p.jsonMarshal(msg.Metadata)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to marshal metadata to JSON")
	}

	req.Header.Set(wmhttp.HeaderMetadata, string(metadataBytes))

	return req, nil
}

func resolveHTTPClient(cfg *Config) *http.Client {
	if cfg.TLSClientConfig == nil {
		return http.DefaultClient
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}
