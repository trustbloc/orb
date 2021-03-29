package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
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
	metadataEventType             = "event_type"
	defaultConcurrentHTTPRequests = 10
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
	ServiceName           string
	ServiceIRI            *url.URL
	Topic                 string
	RedeliveryConfig      *redelivery.Config
	MaxRecipients         int
	MaxConcurrentRequests int
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
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
	client               activityPubClient
	redeliveryService    redeliveryService
	redeliveryChan       chan *message.Message
	jsonMarshal          func(v interface{}) ([]byte, error)
	jsonUnmarshal        func(data []byte, v interface{}) error
}

// New returns a new ActivityPub Outbox.
func New(cfg *Config, s store.Store, pubSub pubSub, httpClient *http.Client,
	handlerOpts ...service.HandlerOpt) (*Outbox, error) {
	options := defaultOptions()

	for _, opt := range handlerOpts {
		opt(options)
	}

	undeliverableChan, err := pubSub.Subscribe(context.Background(), service.UndeliverableTopic)
	if err != nil {
		return nil, err
	}

	redeliverChan := make(chan *message.Message)

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = defaultConcurrentHTTPRequests
	}

	h := &Outbox{
		Config:               cfg,
		undeliverableHandler: options.UndeliverableHandler,
		activityStore:        s,
		client:               client.New(httpClient),
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

	httpPublisher := httppublisher.New(cfg.ServiceName, httpClient)

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

	err = h.activityStore.AddActivity(activity)
	if err != nil {
		return errors.WithMessage(err, "unable to store activity")
	}

	err = h.activityStore.AddReference(store.Outbox, h.ServiceIRI, activity.ID().URL())
	if err != nil {
		return errors.WithMessage(err, "unable to add reference to activity")
	}

	for _, actorInbox := range h.resolveInboxes(activity.To()) {
		err = h.publish(activity.ID().String(), activityBytes, actorInbox)
		if err != nil {
			// TODO: Do we continue processing the rest?
			return fmt.Errorf("unable to publish activity to inbox %s: %w", actorInbox, err)
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

func (h *Outbox) resolveInboxes(toIRIs []*url.URL) []*url.URL {
	return h.resolveIRIs(toIRIs,
		func(actorIRI *url.URL) ([]*url.URL, error) {
			if actorIRI.String() == vocab.PublicIRI {
				// Should not attempt to publish to the 'Public' URL
				logger.Debugf("[%s] Not adding %s to recipients list", h.ServiceName, actorIRI)

				return nil, nil
			}

			if actorIRI.String() == h.ServiceIRI.String() {
				logger.Debugf("[%s] Not adding local service %s to recipients list", h.ServiceName, actorIRI)

				return nil, nil
			}

			inboxIRI, err := h.resolveInbox(actorIRI)
			if err != nil {
				return nil, err
			}

			return []*url.URL{inboxIRI}, nil
		},
	)
}

func (h *Outbox) resolveInbox(iri *url.URL) (*url.URL, error) {
	actor, err := h.activityStore.GetActor(iri)
	if err != nil {
		if err != store.ErrNotFound {
			return nil, fmt.Errorf("unable to load actor %s from storage: %w", iri, err)
		}
	}

	if actor != nil && actor.Inbox() != nil {
		logger.Debugf("[%s] Found actor  %s in local store", h.ServiceName, iri)

		return actor.Inbox(), nil
	}

	logger.Debugf("[%s] Actor not found in local store. Retrieving actor from %s", h.ServiceName, iri)

	actor, err = h.client.GetActor(iri)
	if err != nil {
		return nil, err
	}

	// Add the actor to the local store so that we don't have to retrieve it next time.
	err = h.activityStore.PutActor(actor)
	if err != nil {
		logger.Warnf("[%s] Unable to add actor %s to local storage: %s", h.ServiceName, iri, err)
	}

	return actor.Inbox(), nil
}

// resolveIRIs resolves each of the given IRIs using the given resolve function. The requests are performed
// in parallel, up to a maximum concurrent requests specified by parameter, MaxConcurrentRequests.
func (h *Outbox) resolveIRIs(toIRIs []*url.URL, resolve func(iri *url.URL) ([]*url.URL, error)) []*url.URL {
	var wg sync.WaitGroup

	var recipients []*url.URL

	var mutex sync.Mutex

	wg.Add(len(toIRIs))

	resolveChan := make(chan *url.URL, h.MaxConcurrentRequests)

	go func() {
		for _, iri := range toIRIs {
			resolveChan <- iri
		}
	}()

	go func() {
		for reqIRI := range resolveChan {
			go func(toIRI *url.URL) {
				defer wg.Done()

				r, err := resolve(toIRI)
				if err != nil {
					// TODO: Perform retry.
					logger.Warnf("[%s] Unable to resolve IRIs for %s: %s", h.ServiceName, toIRI, err)
				} else {
					mutex.Lock()
					recipients = append(recipients, r...)
					mutex.Unlock()
				}
			}(reqIRI)
		}
	}()

	wg.Wait()

	close(resolveChan)

	return recipients
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
