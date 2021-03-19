package outbox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/httppublisher"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

const (
	metadataEventType = "event_type"
)

type redeliveryService interface {
	service.ServiceLifecycle

	Add(msg *message.Message) (time.Time, error)
}

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// Config holds configuration parameters for the outbox.
type Config struct {
	ServiceName      string
	Topic            string
	TLSClientConfig  *tls.Config
	RedeliveryConfig *redelivery.Config
}

// Outbox implements the ActivityPub outbox.
type Outbox struct {
	*Config
	*lifecycle.Lifecycle

	router               *message.Router
	httpPublisher        message.Publisher
	publisher            message.Publisher
	undeliverableHandler service.UndeliverableActivityHandler
	undeliverableChan    <-chan *message.Message
	activityStore        store.Store
	redeliveryService    redeliveryService
	redeliveryChan       chan *message.Message
	jsonMarshal          func(v interface{}) ([]byte, error)
	jsonUnmarshal        func(data []byte, v interface{}) error
}

// New returns a new ActivityPub Outbox.
func New(cfg *Config, s store.Store, pubSub pubSub, handlerOpts ...service.HandlerOpt) (*Outbox, error) {
	options := defaultOptions()

	for _, opt := range handlerOpts {
		opt(options)
	}

	undeliverableChan, err := pubSub.Subscribe(context.Background(), service.UndeliverableTopic)
	if err != nil {
		return nil, err
	}

	redeliverChan := make(chan *message.Message)

	h := &Outbox{
		Config:               cfg,
		undeliverableHandler: options.UndeliverableHandler,
		activityStore:        s,
		redeliveryChan:       redeliverChan,
		publisher:            pubSub,
		undeliverableChan:    undeliverableChan,
		redeliveryService:    redelivery.NewService(cfg.ServiceName, cfg.RedeliveryConfig, redeliverChan),
		jsonMarshal:          json.Marshal,
		jsonUnmarshal:        json.Unmarshal,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName,
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	router, err := message.NewRouter(message.RouterConfig{}, wmlogger.New())
	if err != nil {
		panic(err)
	}

	httpPublisher := httppublisher.New(
		&httppublisher.Config{
			ServiceName:     cfg.ServiceName,
			TLSClientConfig: cfg.TLSClientConfig,
		})

	router.AddHandler(
		"outbox-"+cfg.ServiceName, cfg.Topic,
		pubSub, "outbox", httpPublisher,
		func(msg *message.Message) ([]*message.Message, error) {
			return message.Messages{msg}, nil
		},
	)

	router.AddPlugin(plugin.SignalsHandler)

	h.router = router
	h.httpPublisher = httpPublisher

	return h, nil
}

func (h *Outbox) start() {
	// Start the redelivery message listener
	go h.handleRedelivery()

	// Start the redeliver message listener
	go h.redeliver()

	// Start the router
	go h.route()

	h.redeliveryService.Start()

	// Wait for router to start
	<-h.router.Running()
}

func (h *Outbox) stop() {
	h.redeliveryService.Stop()

	close(h.redeliveryChan)

	if err := h.router.Close(); err != nil {
		logger.Warnf("[%s] Error closing router: %s", h.ServiceName, err)
	} else {
		logger.Debugf("[%s] Closed router", h.ServiceName)
	}
}

// Post posts an activity to the outbox.
func (h *Outbox) Post(activity *vocab.ActivityType) error {
	if h.State() != service.StateStarted {
		return service.ErrNotStarted
	}

	activityBytes, err := h.jsonMarshal(activity)
	if err != nil {
		return errors.WithMessage(err, "unable to marshal")
	}

	if err := h.activityStore.AddActivity(store.Outbox, activity); err != nil {
		return errors.WithMessage(err, "unable to store activity")
	}

	for _, to := range activity.To() {
		if err := h.publish(activity.ID().String(), activityBytes, to); err != nil {
			return errors.WithMessage(err, "unable to publish activity")
		}
	}

	return nil
}

func (h *Outbox) publish(id string, activityBytes []byte, to fmt.Stringer) error {
	msg := message.NewMessage(watermill.NewUUID(), activityBytes)
	msg.Metadata.Set(metadataEventType, h.Topic)
	msg.Metadata.Set(httppublisher.MetadataSendTo, to.String())

	middleware.SetCorrelationID(id, msg)

	logger.Debugf("[%s] Publishing %s", h.ServiceName, h.Topic)

	return h.publisher.Publish(h.Topic, msg)
}

func (h *Outbox) route() {
	logger.Infof("Starting router")

	if err := h.router.Run(context.Background()); err != nil {
		// This happens on startup so the best thing to do is to panic
		panic(err)
	}

	logger.Infof("Router is shutting down")
}

func (h *Outbox) handleRedelivery() {
	for msg := range h.undeliverableChan {
		msg.Ack()

		logger.Warnf("[%s] Got undeliverable message [%s]", h.ServiceName, msg.UUID)

		h.handleUndeliverableActivity(msg)
	}
}

func (h *Outbox) handleUndeliverableActivity(msg *message.Message) {
	toURL := msg.Metadata[httppublisher.MetadataSendTo]

	redeliveryTime, err := h.redeliveryService.Add(msg)
	if err != nil {
		activity := &vocab.ActivityType{}
		if e := h.jsonUnmarshal(msg.Payload, activity); e != nil {
			logger.Errorf("[%s] Error unmarshalling activity for message [%s]: %s", h.ServiceName, msg.UUID, e)

			return
		}

		logger.Warnf("[%s] Will not attempt redelivery for message. Activity ID [%s], To: [%s]. Reason: %s",
			h.ServiceName, activity.ID(), toURL, err)

		h.undeliverableHandler.HandleUndeliverableActivity(activity, toURL)
	} else {
		activityID := msg.Metadata[middleware.CorrelationIDMetadataKey]

		logger.Debugf("[%s] Will attempt to redeliver message at %s. Activity ID [%s], To: [%s]",
			h.ServiceName, redeliveryTime, activityID, toURL)
	}
}

func (h *Outbox) redeliver() {
	for msg := range h.redeliveryChan {
		logger.Infof("[%s] Attempting to redeliver message [%s]", h.ServiceName, msg.UUID)

		if err := h.publisher.Publish(h.Topic, msg); err != nil {
			logger.Errorf("[%s] Error redelivering message [%s]: %s", h.ServiceName, msg.UUID, err)
		} else {
			logger.Infof("[%s] Message was delivered: %s", h.ServiceName, msg.UUID)
		}
	}
}

type noOpUndeliverableHandler struct {
}

func (h *noOpUndeliverableHandler) HandleUndeliverableActivity(*vocab.ActivityType, string) {
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		UndeliverableHandler: &noOpUndeliverableHandler{},
	}
}
