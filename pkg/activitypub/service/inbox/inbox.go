/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbox

import (
	"context"
	"encoding/json"
	"net/http"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

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

// Config holds configuration parameters for the Inbox.
type Config struct {
	ServiceName   string
	ListenAddress string
	Topic         string
}

// Inbox implements the ActivityPub inbox.
type Inbox struct {
	*Config
	*lifecycle.Lifecycle

	router          *message.Router
	httpSubscriber  *wmhttp.Subscriber
	msgChannel      <-chan *message.Message
	activityHandler service.ActivityHandler
	activityStore   store.Store
	jsonUnmarshal   func(data []byte, v interface{}) error
}

// New returns a new ActivityPub inbox.
func New(cfg *Config, s store.Store, pubSub pubSub, activityHandler service.ActivityHandler) (*Inbox, error) {
	h := &Inbox{
		Config:          cfg,
		activityHandler: activityHandler,
		activityStore:   s,
		jsonUnmarshal:   json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName, h.start, h.stop)

	msgChan, err := pubSub.Subscribe(context.Background(), cfg.Topic)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to subscribe to topic [%s]", cfg.Topic)
	}

	httpSubscriber, err := wmhttp.NewSubscriber(cfg.ListenAddress, wmhttp.SubscriberConfig{}, wmlogger.New())
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to create HTTP subscriber")
	}

	router, err := message.NewRouter(message.RouterConfig{}, wmlogger.New())
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to create router")
	}

	router.AddMiddleware(middleware.Recoverer, middleware.CorrelationID)

	router.AddPlugin(plugin.SignalsHandler)

	router.AddHandler(
		"inbox-"+cfg.ServiceName, cfg.ServiceName,
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

func (h *Inbox) start() {
	// Start the router
	go h.route()

	// Start the message listener
	go h.listen()

	// HTTP server needs to be started after router is ready.
	<-h.router.Running()

	// Start the HTTP server
	go h.serveHTTP()
}

func (h *Inbox) stop() {
	if err := h.httpSubscriber.Close(); err != nil {
		logger.Warnf("Error closing inbox: %s", err)
	}

	if err := h.router.Close(); err != nil {
		logger.Warnf("[%s] Error closing router: %s", h.ServiceName, err)
	} else {
		logger.Debugf("[%s] Closed router", h.ServiceName)
	}
}

func (h *Inbox) route() {
	logger.Debugf("[%s] Starting router", h.ServiceName)

	if err := h.router.Run(context.Background()); err != nil {
		// This happens on startup so the best thing to do is to panic
		panic(err)
	}

	logger.Debugf("[%s] Router stopped", h.ServiceName)
}

func (h *Inbox) listen() {
	logger.Debugf("[%s] Starting message listener", h.ServiceName)

	for msg := range h.msgChannel {
		logger.Debugf("[%s] Got new message: %s: %s", h.ServiceName, msg.UUID, msg.Payload)

		h.handle(msg)
	}

	logger.Debugf("[%s] Message listener stopped", h.ServiceName)
}

func (h *Inbox) serveHTTP() {
	logger.Debugf("[%s] Starting HTTP server", h.ServiceName)

	if err := h.httpSubscriber.StartHTTPServer(); err != nil {
		if err == http.ErrServerClosed {
			logger.Debugf("[%s] HTTP server stopped", h.ServiceName)
		} else {
			logger.Errorf("[%s] Error starting HTTP server: %s", h.ServiceName, err)

			h.Stop()
		}
	}
}

func (h *Inbox) handle(msg *message.Message) {
	logger.Debugf("[%s] Handling activities message [%s]: %s", h.ServiceName, msg.UUID, msg.Payload)

	activity := &vocab.ActivityType{}

	err := h.jsonUnmarshal(msg.Payload, activity)
	if err != nil {
		logger.Errorf("[%s] Error unmarshalling activity message: %s", h.ServiceName, err)

		msg.Nack()

		return
	}

	if err := h.activityStore.AddActivity(store.Inbox, activity); err != nil {
		logger.Errorf("[%s] Error storing activity [%s]: %s", h.ServiceName, activity.ID(), err)

		msg.Nack()

		return
	}

	if err := h.activityHandler.HandleActivity(activity); err != nil {
		logger.Warnf("[%s] Error handling message [%s]: %s", h.ServiceName, msg.UUID, err)

		msg.Nack()
	} else {
		logger.Warnf("[%s] Successfully handled message [%s]", h.ServiceName, msg.UUID)

		msg.Ack()
	}
}
