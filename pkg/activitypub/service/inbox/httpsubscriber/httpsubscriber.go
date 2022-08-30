/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsubscriber

import (
	"context"
	"net/http"
	"net/url"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.New("activitypub_service")

const (
	// ActorIRIKey is the metadata key for the actor IRI.
	ActorIRIKey = "actor-iri"

	defaultBufferSize = 100
)

// Config holds the HTTP subscriber configuration parameters.
type Config struct {
	ServiceEndpoint string
	BufferSize      int
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// Subscriber implements a subscriber for Watermill that handles HTTP requests.
type Subscriber struct {
	*lifecycle.Lifecycle
	*Config

	pubChan          chan *message.Message
	msgChan          chan *message.Message
	stopped          chan struct{}
	done             chan struct{}
	unmarshalMessage wmhttp.UnmarshalMessageFunc
	verifier         signatureVerifier
	tokenVerifier    *auth.TokenVerifier
}

// New returns a new HTTP subscriber.
func New(cfg *Config, sigVerifier signatureVerifier, tm authTokenManager) *Subscriber {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	s := &Subscriber{
		Config:           cfg,
		unmarshalMessage: wmhttp.DefaultUnmarshalMessageFunc,
		verifier:         sigVerifier,
		pubChan:          make(chan *message.Message, cfg.BufferSize),
		msgChan:          make(chan *message.Message, cfg.BufferSize),
		stopped:          make(chan struct{}),
		done:             make(chan struct{}),
		tokenVerifier:    auth.NewTokenVerifier(tm, cfg.ServiceEndpoint, http.MethodPost),
	}

	s.Lifecycle = lifecycle.New("httpsubscriber-"+cfg.ServiceEndpoint,
		lifecycle.WithStop(s.stop),
		lifecycle.WithStart(func() {
			go s.publisher()
		}),
	)

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
	var actorIRI *url.URL

	if !s.tokenVerifier.Verify(r) {
		logger.Debugf("Request was not verified using authorization bearer tokens. Verifying request via HTTP signature")

		verified, actor, err := s.verifier.VerifyRequest(r)
		if err != nil {
			logger.Errorf("[%s] Error verifying HTTP signature: %s", s.ServiceEndpoint, err)

			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		if !verified {
			logger.Infof("[%s] Invalid HTTP signature", s.ServiceEndpoint)

			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		actorIRI = actor
	} else {
		logger.Debugf("Request was verified with a bearer token or no authorization was required.")
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
	if s.State() != lifecycle.StateStarted {
		return lifecycle.ErrNotStarted
	}

	s.pubChan <- msg

	logger.Debugf("[%s] Message [%s] was posted to publisher", s.ServiceEndpoint, msg.UUID)

	return nil
}

func (s *Subscriber) publisher() {
	logger.Infof("[%s] Starting publisher.", s.ServiceEndpoint)

	for {
		select {
		case msg := <-s.pubChan:
			s.msgChan <- msg

			logger.Debugf("[%s] Message [%s] was delivered to subscriber", s.ServiceEndpoint, msg.UUID)

		case <-s.stopped:
			logger.Infof("[%s] Stopping publisher.", s.ServiceEndpoint)

			close(s.done)

			return
		}
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

		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (s *Subscriber) stop() {
	logger.Infof("[%s] Stopping HTTP subscriber", s.ServiceEndpoint)

	close(s.stopped)

	// Wait for the publisher to stop so that we don't close the message channel
	// while we're trying to publish a message to it (which would result in a panic).
	<-s.done

	close(s.msgChan)

	logger.Infof("[%s] ... HTTP subscriber stopped.", s.ServiceEndpoint)
}
