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
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/service/inbox/httpsubscriber"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

const (
	loggerModule = "activitypub_service"

	defaultSubscriberPoolSize = 5
)

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

type metricsProvider interface {
	InboxHandlerTime(activityType string, value time.Duration)
}

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// Config holds configuration parameters for the Inbox.
type Config struct {
	ServiceEndpoint        string
	ServiceIRI             *url.URL
	Topic                  string
	VerifyActorInSignature bool
	SubscriberPoolSize     int
}

// Inbox implements the ActivityPub inbox.
type Inbox struct {
	*Config
	*lifecycle.Lifecycle

	router                 *message.Router
	httpSubscriber         *httpsubscriber.Subscriber
	msgChannel             <-chan *message.Message
	activityHandler        service.ActivityHandler
	activityStore          store.Store
	jsonUnmarshal          func(data []byte, v interface{}) error
	metrics                metricsProvider
	verifyActorInSignature bool
	logger                 *log.Log
}

// New returns a new ActivityPub inbox.
func New(cnfg *Config, s store.Store, pubSub pubSub, activityHandler service.ActivityHandler,
	sigVerifier signatureVerifier, tm authTokenManager, metrics metricsProvider) (*Inbox, error) {
	cfg := populateConfigDefaults(cnfg)

	h := &Inbox{
		Config:          &cfg,
		activityHandler: activityHandler,
		activityStore:   s,
		jsonUnmarshal:   json.Unmarshal,
		metrics:         metrics,
		logger:          log.New(loggerModule, log.WithFields(logfields.WithServiceName(cfg.ServiceEndpoint))),
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceEndpoint,
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), cfg.Topic, spi.WithPool(cfg.SubscriberPoolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", cfg.Topic, err)
	}

	httpSubscriber := httpsubscriber.New(
		&httpsubscriber.Config{
			ServiceEndpoint: cfg.ServiceEndpoint,
		},
		sigVerifier, tm,
	)

	router, err := message.NewRouter(message.RouterConfig{}, wmlogger.New())
	if err != nil {
		return nil, fmt.Errorf("create router: %w", err)
	}

	router.AddMiddleware(middleware.Recoverer, middleware.CorrelationID)

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

	requiredTokens, err := tm.RequiredAuthTokens(h.ServiceEndpoint, http.MethodPost)
	if err != nil {
		return nil, fmt.Errorf("required auth tokens: %w", err)
	}

	h.verifyActorInSignature = cfg.VerifyActorInSignature && len(requiredTokens) > 0

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
		h.logger.Warn("Error closing router", log.WithError(err))
	} else {
		h.logger.Debug("Closed router")
	}
}

func (h *Inbox) route() {
	h.logger.Debug("Starting router")

	if err := h.router.Run(context.Background()); err != nil {
		// This happens on startup so the best thing to do is to panic
		panic(err)
	}

	h.logger.Debug("Router stopped")
}

func (h *Inbox) listen() {
	h.logger.Debug("Starting message listener")

	for msg := range h.msgChannel {
		h.logger.Debug("Got new message", logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

		h.handle(msg)
	}

	h.logger.Debug("Message listener stopped")
}

func (h *Inbox) handle(msg *message.Message) {
	startTime := time.Now()

	activity, err := h.handleActivityMsg(msg)
	if err != nil {
		if orberrors.IsTransient(err) {
			h.logger.Warn("Transient error handling message", logfields.WithMessageID(msg.UUID), log.WithError(err))

			msg.Nack()
		} else {
			h.logger.Warn("Persistent error handling message", logfields.WithMessageID(msg.UUID), log.WithError(err))

			// Ack the message to indicate that it should not be redelivered since this is a persistent error.
			msg.Ack()
		}
	} else {
		h.logger.Debug("Acking message", logfields.WithMessageID(msg.UUID), logfields.WithActivityID(activity.ID()))

		msg.Ack()

		h.metrics.InboxHandlerTime(activity.Type().String(), time.Since(startTime))
	}
}

func (h *Inbox) handleActivityMsg(msg *message.Message) (*vocab.ActivityType, error) {
	h.logger.Debug("Handling activities message",
		logfields.WithMessageID(msg.UUID), logfields.WithData(msg.Payload))

	activity, err := h.unmarshalAndValidateActivity(msg)
	if err != nil {
		h.logger.Error("Error validating activity", log.WithError(err), logfields.WithMessageID(msg.UUID))

		return nil, err
	}

	_, err = h.activityStore.GetActivity(activity.ID().URL())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.logger.Error("Error retrieving activity", log.WithError(err),
				logfields.WithActivityID(activity.ID()), logfields.WithMessageID(msg.UUID))

			return nil, err
		}
	} else {
		h.logger.Info("Ignoring duplicate activity", logfields.WithActivityID(activity.ID()), logfields.WithMessageID(msg.UUID))

		return activity, nil
	}

	err = h.activityHandler.HandleActivity(nil, activity)
	if err != nil {
		// If it's a transient error then return it so that the message is Nacked and retried. Otherwise, fall
		// through in order to store the activity and Ack the message.
		if orberrors.IsTransient(err) {
			return nil, err
		}
	}

	h.logger.Debug("Handled message. Adding activity to inbox...",
		logfields.WithMessageID(msg.UUID), logfields.WithActivityID(activity.ID()))

	// Don't return an error if we can't store the activity since we've already successfully processed the activity,
	// and we don't want to reprocess the same message.
	if e := h.activityStore.AddActivity(activity); e != nil {
		h.logger.Error("Error storing activity", log.WithError(e), logfields.WithActivityID(activity.ID()))
	} else if e := h.activityStore.AddReference(store.Inbox, h.ServiceIRI, activity.ID().URL(),
		store.WithActivityType(activity.Type().Types()[0])); e != nil {
		h.logger.Error("Error adding reference to activity", log.WithError(e), logfields.WithActivityID(activity.ID()))
	}

	return activity, err
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

	if h.verifyActorInSignature {
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

func populateConfigDefaults(cnfg *Config) Config {
	cfg := *cnfg

	if cfg.SubscriberPoolSize == 0 {
		cfg.SubscriberPoolSize = defaultSubscriberPoolSize
	}

	return cfg
}
