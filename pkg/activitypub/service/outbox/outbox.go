/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/httppublisher"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/redelivery"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

var logger = log.New("activitypub_service")

const (
	metadataEventType             = "event_type"
	defaultConcurrentHTTPRequests = 10
	defaultCacheSize              = 100
	defaultCacheExpiration        = time.Minute
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
	CacheSize             int
	CacheExpiration       time.Duration
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
	GetReferences(iri *url.URL) (client.ReferenceIterator, error)
}

type resourceResolver interface {
	ResolveHostMetaLink(uri, linkType string) (string, error)
}

// Outbox implements the ActivityPub outbox.
type Outbox struct {
	*Config
	*lifecycle.Lifecycle

	router               *message.Router
	httpPublisher        message.Publisher
	publisher            message.Publisher
	activityHandler      service.ActivityHandler
	undeliverableHandler service.UndeliverableActivityHandler
	undeliverableChan    <-chan *message.Message
	activityStore        store.Store
	client               activityPubClient
	resourceResolver     resourceResolver
	redeliveryService    redeliveryService
	redeliveryChan       chan *message.Message
	jsonMarshal          func(v interface{}) ([]byte, error)
	jsonUnmarshal        func(data []byte, v interface{}) error
	iriCache             gcache.Cache
	metrics              metricsProvider
}

type httpTransport interface {
	Post(ctx context.Context, req *transport.Request, payload []byte) (*http.Response, error)
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

type metricsProvider interface {
	OutboxPostTime(value time.Duration)
	OutboxResolveInboxesTime(value time.Duration)
	OutboxIncrementActivityCount(activityType string)
}

// New returns a new ActivityPub Outbox.
//nolint:funlen
func New(cnfg *Config, s store.Store, pubSub pubSub, t httpTransport, activityHandler service.ActivityHandler,
	apClient activityPubClient, resourceResolver resourceResolver, metrics metricsProvider,
	handlerOpts ...service.HandlerOpt) (*Outbox, error) {
	options := newHandlerOptions(handlerOpts)

	undeliverableChan, err := pubSub.Subscribe(context.Background(), spi.UndeliverableTopic)
	if err != nil {
		return nil, err
	}

	cfg := populateConfigDefaults(cnfg)

	redeliverChan := make(chan *message.Message, cfg.RedeliveryConfig.MaxMessages)

	h := &Outbox{
		Config:               &cfg,
		activityHandler:      activityHandler,
		undeliverableHandler: options.UndeliverableHandler,
		activityStore:        s,
		client:               apClient,
		resourceResolver:     resourceResolver,
		redeliveryChan:       redeliverChan,
		publisher:            pubSub,
		undeliverableChan:    undeliverableChan,
		redeliveryService:    redelivery.NewService(cfg.ServiceName, cfg.RedeliveryConfig, redeliverChan),
		jsonMarshal:          json.Marshal,
		jsonUnmarshal:        json.Unmarshal,
		metrics:              metrics,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName,
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	logger.Debugf("Creating IRI cache with size=%d, expiration=%s", cfg.CacheSize, cfg.CacheExpiration)

	h.iriCache = gcache.New(cfg.CacheSize).ARC().
		Expiration(cfg.CacheExpiration).
		LoaderFunc(func(i interface{}) (interface{}, error) {
			return h.doResolveActorIRIs(i.(*url.URL))
		}).Build()

	router, err := message.NewRouter(message.RouterConfig{}, wmlogger.New())
	if err != nil {
		panic(err)
	}

	httpPublisher := httppublisher.New(cfg.ServiceName, t)

	router.AddHandler(
		"outbox-"+cfg.ServiceName, cfg.Topic,
		pubSub, "outbox", httpPublisher,
		func(msg *message.Message) ([]*message.Message, error) {
			return message.Messages{msg}, nil
		},
	)

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

// Post posts an activity to the outbox and returns the ID of the activity that was posted.
// If the activity does not specify an ID then a unique ID will be generated. The 'actor' of the
// activity is also assigned to the service IRI of the outbox. An exclude list may be provided
// so that the activity is not posted to the given URLs.
func (h *Outbox) Post(activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error) {
	if h.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	h.incrementCount(activity.Type().Types())

	startTime := time.Now()
	defer func() {
		h.metrics.OutboxPostTime(time.Since(startTime))
	}()

	activity, err := h.validateAndPopulateActivity(activity)
	if err != nil {
		return nil, err
	}

	activityBytes, err := h.jsonMarshal(activity)
	if err != nil {
		return nil, orberrors.NewBadRequest(fmt.Errorf("marshal: %w", err))
	}

	logger.Debugf("[%s] Posting activity: %s", h.ServiceName, activityBytes)

	err = h.storeActivity(activity)
	if err != nil {
		return nil, fmt.Errorf("store activity: %w", err)
	}

	err = h.activityHandler.HandleActivity(nil, activity)
	if err != nil {
		return nil, fmt.Errorf("handle activity: %w", err)
	}

	inboxes, err := h.resolveInboxes(activity.To(), exclude)
	if err != nil {
		return nil, fmt.Errorf("resolve inboxes: %w", err)
	}

	for _, actorInbox := range inboxes {
		err = h.publish(activity.ID().String(), activityBytes, actorInbox)
		if err != nil {
			// TODO: Do we continue processing the rest?
			return nil, fmt.Errorf("unable to publish activity to inbox %s: %w", actorInbox, err)
		}
	}

	return activity.ID().URL(), nil
}

func (h *Outbox) storeActivity(activity *vocab.ActivityType) error {
	if err := h.activityStore.AddActivity(activity); err != nil {
		return fmt.Errorf("store activity: %w", err)
	}

	if err := h.activityStore.AddReference(store.Outbox, h.ServiceIRI, activity.ID().URL(),
		store.WithActivityType(activity.Type().Types()[0])); err != nil {
		return fmt.Errorf("add reference to activity: %w", err)
	}

	if activity.To().Contains(vocab.PublicIRI) {
		if err := h.activityStore.AddReference(store.PublicOutbox, h.ServiceIRI, activity.ID().URL(),
			store.WithActivityType(activity.Type().Types()[0])); err != nil {
			return fmt.Errorf("add reference to activity: %w", err)
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

func (h *Outbox) resolveInboxes(toIRIs, excludeIRIs []*url.URL) ([]*url.URL, error) {
	startTime := time.Now()

	defer func() {
		h.metrics.OutboxResolveInboxesTime(time.Since(startTime))
	}()

	toIRIs, err := h.resolveIRIs(toIRIs, h.resolveActorIRIs)
	if err != nil {
		return nil, err
	}

	return h.resolveIRIs(
		deduplicateAndFilter(toIRIs, excludeIRIs),
		func(actorIRI *url.URL) ([]*url.URL, error) {
			inboxIRI, err := h.resolveInbox(actorIRI)
			if err != nil {
				return nil, err
			}

			return []*url.URL{inboxIRI}, nil
		},
	)
}

func (h *Outbox) resolveInbox(iri *url.URL) (*url.URL, error) {
	logger.Debugf("[%s] Retrieving actor from %s", h.ServiceName, iri)

	actor, err := h.client.GetActor(iri)
	if err != nil {
		return nil, err
	}

	return actor.Inbox(), nil
}

func (h *Outbox) resolveActorIRIs(iri *url.URL) ([]*url.URL, error) {
	if iri.String() == vocab.PublicIRI.String() {
		// Should not attempt to publish to the 'Public' URI.
		logger.Debugf("[%s] Not adding %s to recipients list", h.ServiceName, iri)

		return nil, nil
	}

	result, err := h.iriCache.Get(iri)
	if err != nil {
		logger.Debugf("[%s] Got error resolving IRI from cache for actor [%s]: %s", h.ServiceName, iri, err)

		return nil, err
	}

	return result.([]*url.URL), nil
}

func (h *Outbox) doResolveActorIRIs(iri *url.URL) ([]*url.URL, error) {
	logger.Debugf("[%s] Resolving IRI for actor [%s]", h.ServiceName, iri)

	if strings.HasPrefix(iri.String(), h.ServiceIRI.String()) {
		// This IRI is for the local service. The only valid paths are /followers and /witnesses.
		switch {
		case strings.HasSuffix(iri.Path, resthandler.FollowersPath):
			return h.loadReferences(store.Follower)
		case strings.HasSuffix(iri.Path, resthandler.WitnessesPath):
			return h.loadReferences(store.Witness)
		default:
			logger.Warnf("[%s] Ignoring local IRI %s since it is not a valid recipient.", h.ServiceName, iri)

			return nil, nil
		}
	}

	// Resolve the actor IRI from WebFinger.
	resolvedActorIRI, err := h.resourceResolver.ResolveHostMetaLink(iri.String(), discoveryrest.ActivityJSONType)
	if err != nil {
		return nil, fmt.Errorf("resolve actor: %w", err)
	}

	logger.Debugf("[%s] Resolved IRI for actor [%s]: [%s]", h.ServiceName, iri, resolvedActorIRI)

	actorURI, err := url.Parse(resolvedActorIRI)
	if err != nil {
		return nil, fmt.Errorf("parse actor URI: %w", err)
	}

	logger.Debugf("[%s] Sending request to %s to resolve recipient list", h.ServiceName, actorURI)

	it, err := h.client.GetReferences(actorURI)
	if err != nil {
		return nil, err
	}

	return client.ReadReferences(it, h.MaxRecipients)
}

func (h *Outbox) loadReferences(refType store.ReferenceType) ([]*url.URL, error) {
	logger.Debugf("[%s] Loading references from local storage", h.ServiceName)

	it, err := h.activityStore.QueryReferences(refType, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
	if err != nil {
		return nil, fmt.Errorf("error querying for references of type %s from storage: %w", refType, err)
	}

	refs, err := storeutil.ReadReferences(it, h.MaxRecipients)
	if err != nil {
		return nil, fmt.Errorf("error retrieving references of type %s from storage: %w", refType, err)
	}

	logger.Debugf("[%s] Got %d references from local storage", h.ServiceName, len(refs))

	return refs, nil
}

// resolveIRIs resolves each of the given IRIs using the given resolve function. The requests are performed
// in parallel, up to a maximum concurrent requests specified by parameter, MaxConcurrentRequests.
func (h *Outbox) resolveIRIs(toIRIs []*url.URL, resolve func(iri *url.URL) ([]*url.URL, error)) ([]*url.URL, error) {
	var wg sync.WaitGroup

	var recipients []*url.URL

	var errResolve error

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
					// Check if transient. We can retry on transient errors, otherwise ignore the IRI.
					if orberrors.IsTransient(err) {
						logger.Warnf("[%s] Unable to resolve IRIs for %s due to transient error: %s",
							h.ServiceName, toIRI, err)

						mutex.Lock()
						errResolve = err
						mutex.Unlock()
					} else {
						logger.Warnf("[%s] Unable to resolve IRIs for %s due to persistent error: %s. The IRI will be ignored.",
							h.ServiceName, toIRI, err)
					}
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

	if errResolve != nil {
		return nil, errResolve
	}

	return recipients, nil
}

func (h *Outbox) newActivityID() *url.URL {
	id, err := url.Parse(fmt.Sprintf("%s/activities/%s", h.ServiceIRI, uuid.New()))
	if err != nil {
		// Should never happen since we've already validated the URLs
		panic(err)
	}

	return id
}

func (h *Outbox) validateAndPopulateActivity(activity *vocab.ActivityType) (*vocab.ActivityType, error) {
	if activity.ID() == nil {
		activity.SetID(h.newActivityID())
	}

	if activity.Actor() != nil {
		if activity.Actor().String() != h.ServiceIRI.String() {
			return nil, orberrors.NewBadRequest(fmt.Errorf("invalid actor IRI"))
		}
	} else {
		activity.SetActor(h.ServiceIRI)
	}

	return activity, nil
}

func (h *Outbox) incrementCount(types []vocab.Type) {
	for _, activityType := range types {
		h.metrics.OutboxIncrementActivityCount(string(activityType))
	}
}

func populateConfigDefaults(cnfg *Config) Config {
	cfg := *cnfg

	if cfg.RedeliveryConfig == nil {
		cfg.RedeliveryConfig = redelivery.DefaultConfig()
	}

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = defaultConcurrentHTTPRequests
	}

	if cfg.CacheSize == 0 {
		cfg.CacheSize = defaultCacheSize
	}

	if cfg.CacheExpiration == 0 {
		cfg.CacheExpiration = defaultCacheExpiration
	}

	return cfg
}

func deduplicateAndFilter(toIRIs, excludeIRIs []*url.URL) []*url.URL {
	m := make(map[string]struct{})

	var iris []*url.URL

	for _, iri := range toIRIs {
		strIRI := iri.String()

		if _, exists := m[strIRI]; !exists && !contains(excludeIRIs, iri) {
			iris = append(iris, iri)
			m[strIRI] = struct{}{}
		}
	}

	return iris
}

type noOpUndeliverableHandler struct{}

func (h *noOpUndeliverableHandler) HandleUndeliverableActivity(*vocab.ActivityType, string) {
}

func newHandlerOptions(opts []service.HandlerOpt) *service.Handlers {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	return options
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		UndeliverableHandler: &noOpUndeliverableHandler{},
	}
}

func contains(arr []*url.URL, u *url.URL) bool {
	for _, s := range arr {
		if s.String() == u.String() {
			return true
		}
	}

	return false
}
