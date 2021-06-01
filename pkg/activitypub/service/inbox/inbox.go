/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	aperrors "github.com/trustbloc/orb/pkg/activitypub/errors"
	"github.com/trustbloc/orb/pkg/activitypub/service/inbox/httpsubscriber"
	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// Config holds configuration parameters for the Inbox.
type Config struct {
	ServiceEndpoint        string
	ServiceIRI             *url.URL
	Topic                  string
	VerifyActorInSignature bool
}

// Inbox implements the ActivityPub inbox.
type Inbox struct {
	*Config
	*lifecycle.Lifecycle

	router          *message.Router
	httpSubscriber  *httpsubscriber.Subscriber
	pubSub          pubSub
	msgChannel      <-chan *message.Message
	activityHandler service.ActivityHandler
	activityStore   store.Store
	jsonUnmarshal   func(data []byte, v interface{}) error
}

// New returns a new ActivityPub inbox.
func New(cfg *Config, s store.Store, pubSub pubSub, activityHandler service.ActivityHandler,
	sigVerifier signatureVerifier) (*Inbox, error) {
	h := &Inbox{
		Config:          cfg,
		activityHandler: activityHandler,
		activityStore:   s,
		pubSub:          pubSub,
		jsonUnmarshal:   json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceEndpoint,
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	msgChan, err := pubSub.Subscribe(context.Background(), cfg.Topic)
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", cfg.Topic, err)
	}

	httpSubscriber := httpsubscriber.New(
		&httpsubscriber.Config{
			ServiceEndpoint: cfg.ServiceEndpoint,
		},
		sigVerifier,
	)

	router, err := message.NewRouter(message.RouterConfig{}, wmlogger.New())
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	router.AddMiddleware(middleware.Recoverer, middleware.CorrelationID)

	router.AddPlugin(plugin.SignalsHandler)

	router.AddHandler(
		cfg.ServiceEndpoint, cfg.ServiceEndpoint,
		httpSubscriber, cfg.Topic, pubSub,
		func(msg *message.Message) ([]*message.Message, error) {
			// Simply forward the message.
			return message.Messages{msg}, nil
		},
	)

	h.router = router
	h.httpSubscriber = httpSubscriber
	h.msgChannel = msgChan

	return h, nil
}

// HTTPHandler returns the HTTP handler which is invoked by the HTTP server.
// This handler must be registered with an HTTP server.
func (h *Inbox) HTTPHandler() common.HTTPHandler {
	return h.httpSubscriber
}

func (h *Inbox) start() {
	// Start the router
	go h.route()

	// Start the message listener
	go h.listen()

	// HTTP server needs to be started after router is ready.
	<-h.router.Running()
}

func (h *Inbox) stop() {
	if err := h.router.Close(); err != nil {
		logger.Warnf("[%s] Error closing router: %s", h.ServiceEndpoint, err)
	} else {
		logger.Debugf("[%s] Closed router", h.ServiceEndpoint)
	}
}

func (h *Inbox) route() {
	logger.Debugf("[%s] Starting router", h.ServiceEndpoint)

	if err := h.router.Run(context.Background()); err != nil {
		// This happens on startup so the best thing to do is to panic
		panic(err)
	}

	logger.Debugf("[%s] Router stopped", h.ServiceEndpoint)
}

func (h *Inbox) listen() {
	logger.Debugf("[%s] Starting message listener", h.ServiceEndpoint)

	for msg := range h.msgChannel {
		logger.Debugf("[%s] Got new message: %s: %s", h.ServiceEndpoint, msg.UUID, msg.Payload)

		h.handle(msg)
	}

	logger.Debugf("[%s] Message listener stopped", h.ServiceEndpoint)
}

func (h *Inbox) handle(msg *message.Message) {
	logger.Debugf("[%s] Handling activities message [%s]: %s", h.ServiceEndpoint, msg.UUID, msg.Payload)

	activity, err := h.unmarshalAndValidateActivity(msg)
	if err != nil {
		logger.Errorf("[%s] Error validating activity for message [%s]: %s", h.ServiceEndpoint, msg.UUID, err)

		// Ack the message to indicate that it should not be redelivered since this is a persistent error.
		msg.Ack()

		return
	}

	activityID, err := h.activityStore.GetActivity(activity.ID().URL())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			logger.Errorf("[%s] Error retrieving activity [%s] in message [%s]: %s",
				h.ServiceEndpoint, activity.ID(), msg.UUID, err)

			msg.Nack()

			return
		}
	} else {
		logger.Infof("[%s] Ignoring duplicate activity [%s] in message [%s]", h.ServiceEndpoint, activityID, msg.UUID)

		msg.Ack()

		return
	}

	if e := h.activityHandler.HandleActivity(activity); e != nil {
		if aperrors.IsTransient(e) {
			logger.Warnf("[%s] Transient error handling message [%s]: %s", h.ServiceEndpoint, msg.UUID, e)

			// Nack the message so that it may be retried (potentially on a different server).
			msg.Nack()

			return
		}

		logger.Warnf("[%s] Persistent error handling message [%s]: %s", h.ServiceEndpoint, msg.UUID, e)
	}

	logger.Debugf("[%s] Successfully handled message [%s]. Adding activity to inbox...", h.ServiceEndpoint, msg.UUID)

	if e := h.activityStore.AddActivity(activity); e != nil {
		logger.Errorf("[%s] Error storing activity [%s]: %s", h.ServiceEndpoint, activity.ID(), e)
	} else if e := h.activityStore.AddReference(store.Inbox, h.ServiceIRI, activity.ID().URL()); e != nil {
		logger.Errorf("[%s] Error adding reference to activity [%s]: %s", h.ServiceEndpoint, activity.ID(), e)
	}

	// An Ack is sent on successful processing (even if an error occurs while attempting to store the activity to
	// the inbox) and in the case of a persistent error (so that a retry is not attempted).
	msg.Ack()
}

func (h *Inbox) unmarshalAndValidateActivity(msg *message.Message) (*vocab.ActivityType, error) {
	activity := &vocab.ActivityType{}

	err := h.jsonUnmarshal(msg.Payload, activity)
	if err != nil {
		return nil, fmt.Errorf("unmarshal activity: %w", err)
	}

	if activity.Actor() == nil {
		return nil, fmt.Errorf("no actor specified in activity [%s]", activity.ID())
	}

	if h.VerifyActorInSignature {
		actorIRI := msg.Metadata[httpsubscriber.ActorIRIKey]
		if actorIRI == "" {
			return nil, fmt.Errorf("no actorIRI specified in message context")
		}

		if activity.Actor().String() != actorIRI {
			return nil, fmt.Errorf("actor in activity [%s] does not match the actor in the HTTP signature [%s]",
				activity.ID(), actorIRI)
		}
	}

	return activity, nil
}
