/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsubscriber

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.New("activitypub_service")

const (
	// ActorIRIKey is the metadata key for the actor IRI.
	ActorIRIKey = "actor-iri"

	defaultBufferSize = 100
	stopTimeout       = 250 * time.Millisecond
)

// Config holds the HTTP subscriber configuration parameters.
type Config struct {
	ServiceEndpoint string
	BufferSize      int
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// Subscriber implements a subscriber for Watermill that handles HTTP requests.
type Subscriber struct {
	*lifecycle.Lifecycle
	*Config

	msgChan          chan *message.Message
	stopped          chan struct{}
	done             chan struct{}
	unmarshalMessage wmhttp.UnmarshalMessageFunc
	verifier         signatureVerifier
}

// New returns a new HTTP subscriber.
func New(cfg *Config, sigVerifier signatureVerifier) *Subscriber {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	s := &Subscriber{
		Config:           cfg,
		unmarshalMessage: wmhttp.DefaultUnmarshalMessageFunc,
		verifier:         sigVerifier,
		msgChan:          make(chan *message.Message, cfg.BufferSize),
		stopped:          make(chan struct{}),
		done:             make(chan struct{}),
	}

	s.Lifecycle = lifecycle.New("httpsubscriber-"+cfg.ServiceEndpoint, lifecycle.WithStop(s.stop))

	// Start the service immediately.
	s.Start()

	return s
}

// Subscribe returns the channel over which incoming messages are sent.
func (s *Subscriber) Subscribe(_ context.Context, _ string) (<-chan *message.Message, error) {
	return s.msgChan, nil
}

// Close stops the subscriber.
func (s *Subscriber) Close() error {
	s.Stop()

	return nil
}

// Path returns the base path of the target endpoint for this subscriber.
func (s *Subscriber) Path() string {
	return s.ServiceEndpoint
}

// Method returns the HTTP method, which is always POST.
func (s *Subscriber) Method() string {
	return http.MethodPost
}

// Handler returns the handler that should be invoked when an HTTP request is posted to the target endpoint.
// This handler must be registered with an HTTP server.
func (s *Subscriber) Handler() common.HTTPRequestHandler {
	return s.handleMessage
}

func (s *Subscriber) handleMessage(w http.ResponseWriter, r *http.Request) {
	ok, actorIRI, err := s.verifier.VerifyRequest(r)
	if err != nil {
		logger.Errorf("[%s] Error verifying HTTP signature: %s", s.ServiceEndpoint, err)

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	if !ok {
		logger.Infof("[%s] Invalid HTTP signature", s.ServiceEndpoint)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	msg, err := s.unmarshalMessage("", r)
	if err != nil {
		logger.Warnf("[%s] Error reading message: %s", s.ServiceEndpoint, err)

		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if actorIRI != nil {
		msg.Metadata[ActorIRIKey] = actorIRI.String()
	}

	logger.Debugf("[%s] Handling message [%s] from actor [%s]", s.ServiceEndpoint, msg.UUID, actorIRI)

	err = s.publish(msg)
	if err != nil {
		logger.Infof("[%s] Message [%s] wasn't sent: %s", s.ServiceEndpoint, msg.UUID, err)

		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	s.respond(msg, w, r)
}

func (s *Subscriber) publish(msg *message.Message) error {
	select {
	case s.msgChan <- msg:
		logger.Debugf("[%s] Message [%s] was delivered to subscriber", s.ServiceEndpoint, msg.UUID)

		return nil

	case <-s.stopped:
		logger.Infof("[%s] Message [%s] was not published since service was stopped", s.ServiceEndpoint, msg.UUID)

		s.done <- struct{}{}

		return fmt.Errorf("service stopped")
	}
}

func (s *Subscriber) respond(msg *message.Message, w http.ResponseWriter, r *http.Request) {
	select {
	case <-msg.Acked():
		logger.Debugf("[%s] Ack received for message [%s]", s.ServiceEndpoint, msg.UUID)

		w.WriteHeader(http.StatusOK)

	case <-msg.Nacked():
		logger.Warnf("[%s] Nack received for message [%s]", s.ServiceEndpoint, msg.UUID)

		w.WriteHeader(http.StatusInternalServerError)

	case <-r.Context().Done():
		logger.Infof("[%s] Timed out waiting for ack or nack for message [%s]",
			s.ServiceEndpoint, msg.UUID, r.Context().Err())

		w.WriteHeader(http.StatusInternalServerError)

	case <-s.stopped:
		logger.Infof("[%s] Message [%s] was not handled since service was stopped", s.ServiceEndpoint, msg.UUID)

		s.done <- struct{}{}

		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (s *Subscriber) stop() {
	logger.Infof("[%s] Stopping HTTP subscriber", s.ServiceEndpoint)

	close(s.stopped)

	// Wait for the publisher to stop so that we don't close the message channel
	// while we're trying to publish a message to it (which would result in a panic).

	select {
	case <-s.done:
	case <-time.After(stopTimeout):
	}

	close(s.msgChan)

	logger.Infof("[%s] ... HTTP subscriber stopped.", s.ServiceEndpoint)
}
