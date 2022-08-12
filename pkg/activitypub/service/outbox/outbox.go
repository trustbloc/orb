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
	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("activitypub_service")

const (
	defaultConcurrentHTTPRequests = 10
	defaultCacheSize              = 100
	defaultCacheExpiration        = time.Minute
	defaultSubscriberPoolSize     = 5
)

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// Config holds configuration parameters for the outbox.
type Config struct {
	ServiceName           string
	ServiceIRI            *url.URL
	ServiceEndpointURL    *url.URL
	Topic                 string
	MaxRecipients         int
	MaxConcurrentRequests int
	CacheSize             int
	CacheExpiration       time.Duration
	SubscriberPoolSize    int
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

	httpTransport    httpTransport
	publisher        message.Publisher
	activityHandler  service.ActivityHandler
	msgChan          <-chan *message.Message
	activityStore    store.Store
	client           activityPubClient
	resourceResolver resourceResolver
	jsonMarshal      func(v interface{}) ([]byte, error)
	jsonUnmarshal    func(data []byte, v interface{}) error
	iriCache         gcache.Cache
	metrics          metricsProvider
	followersPath    string
	witnessesPath    string
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
func New(cnfg *Config, s store.Store, pubSub pubSub, t httpTransport, activityHandler service.ActivityHandler,
	apClient activityPubClient, resourceResolver resourceResolver, metrics metricsProvider) (*Outbox, error) {
	cfg := populateConfigDefaults(cnfg)

	logger.Debugf("Creating Outbox with config: %+v", cfg)

	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), cfg.Topic, spi.WithPool(cfg.SubscriberPoolSize))
	if err != nil {
		return nil, err
	}

	h := &Outbox{
		Config:           &cfg,
		activityHandler:  activityHandler,
		activityStore:    s,
		client:           apClient,
		resourceResolver: resourceResolver,
		publisher:        pubSub,
		msgChan:          msgChan,
		jsonMarshal:      json.Marshal,
		jsonUnmarshal:    json.Unmarshal,
		metrics:          metrics,
		httpTransport:    t,
		followersPath:    cfg.ServiceEndpointURL.String() + resthandler.FollowersPath,
		witnessesPath:    cfg.ServiceEndpointURL.String() + resthandler.WitnessesPath,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName,
		lifecycle.WithStart(h.start),
		lifecycle.WithStop(h.stop),
	)

	logger.Debugf("Creating IRI cache with size=%d, expiration=%s", cfg.CacheSize, cfg.CacheExpiration)

	h.iriCache = gcache.New(cfg.CacheSize).ARC().
		Expiration(cfg.CacheExpiration).
		LoaderFunc(func(i interface{}) (interface{}, error) {
			return h.resolveActorIRI(i.(*url.URL))
		}).Build()

	return h, nil
}

func (h *Outbox) start() {
	go h.listen()
}

func (h *Outbox) stop() {
	logger.Infof("[%s] Outbox stopped", h.ServiceName)
}

func (h *Outbox) listen() {
	logger.Debugf("[%s] Starting message listener", h.ServiceName)

	for msg := range h.msgChan {
		logger.Debugf("[%s] Got new message: %s: %s", h.ServiceName, msg.UUID, msg.Payload)

		h.handle(msg)
	}

	logger.Debugf("[%s] Message listener stopped", h.ServiceName)
}

type messageType string

const (
	broadcastType         messageType = "broadcast"
	deliverType           messageType = "deliver"
	resolveAndDeliverType messageType = "resolve-and-deliver"
)

type activityMessage struct {
	Type        messageType                  `json:"type"`
	Activity    *vocab.ActivityType          `json:"activity"`
	TargetIRI   *vocab.URLProperty           `json:"target,omitempty"`
	TargetIRIs  *vocab.URLCollectionProperty `json:"targets,omitempty"`
	ExcludeIRIs *vocab.URLCollectionProperty `json:"exclude,omitempty"`
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

	err = h.publishBroadcastMessage(activity, exclude)
	if err != nil {
		return nil, fmt.Errorf("publish activity message [%s]: %w", activity.ID(), err)
	}

	return activity.ID().URL(), nil
}

func (h *Outbox) handle(msg *message.Message) {
	activity, err := h.handleActivityMsg(msg)
	if err != nil {
		if orberrors.IsTransient(err) {
			logger.Warnf("[%s] Transient error handling message [%s]: %s",
				h.ServiceName, msg.UUID, err)

			msg.Nack()
		} else {
			logger.Warnf("[%s] Persistent error handling message [%s]: %s",
				h.ServiceName, msg.UUID, err)

			// Ack the message to indicate that it should not be redelivered since this is a persistent error.
			msg.Ack()
		}
	} else {
		logger.Debugf("[%s] Acking message [%s] for activity [%s]", h.ServiceName, msg.UUID, activity.ID())

		msg.Ack()
	}
}

func (h *Outbox) handleActivityMsg(msg *message.Message) (*vocab.ActivityType, error) {
	logger.Debugf("[%s] Handling activity message [%s]", h.ServiceName, msg.UUID)

	activityMsg := &activityMessage{}

	if err := h.jsonUnmarshal(msg.Payload, activityMsg); err != nil {
		return nil, fmt.Errorf("unmarshal activity message [%s]: %w", msg.UUID, err)
	}

	switch activityMsg.Type {
	case broadcastType:
		logger.Debugf("[%s] Handling 'broadcast' activity message [%s], activity [%s]",
			h.ServiceName, msg.UUID, activityMsg.Activity.ID())

		if err := h.handleBroadcast(activityMsg.Activity, activityMsg.ExcludeIRIs.URLs()); err != nil {
			return nil, fmt.Errorf("handle 'broadcast' message for activity [%s]: %w",
				activityMsg.Activity.ID(), err)
		}

		return activityMsg.Activity, nil

	case resolveAndDeliverType:
		logger.Debugf("[%s] Handling 'resolve-and-deliver' message [%s], activity [%s], target %s",
			h.ServiceName, msg.UUID, activityMsg.Activity.ID(), activityMsg.TargetIRI)

		if err := h.handleResolveIRIs(activityMsg.Activity, activityMsg.TargetIRI.URL(),
			activityMsg.ExcludeIRIs.URLs()); err != nil {
			return nil, fmt.Errorf("handle 'resolve-and-deliver' message for activity [%s] of type [%s] to [%s]: %w",
				activityMsg.Activity.ID(), activityMsg.Activity.Type(), activityMsg.TargetIRI, err)
		}

		return activityMsg.Activity, nil

	case deliverType:
		logger.Debugf("[%s] Handling 'deliver' activity message [%s], activity [%s], target [%s]",
			h.ServiceName, msg.UUID, activityMsg.Activity.ID(), activityMsg.TargetIRI)

		if err := h.sendActivity(activityMsg.Activity, activityMsg.TargetIRI.URL()); err != nil {
			return nil, fmt.Errorf("handle 'deliver' message for activity [%s] of type [%s] to [%s]: %w",
				activityMsg.Activity.ID(), activityMsg.Activity.Type(), activityMsg.TargetIRI, err)
		}

		return activityMsg.Activity, nil

	default:
		return nil, fmt.Errorf("unsupported activity message type [%s]", activityMsg.Type)
	}
}

func (h *Outbox) handleBroadcast(activity *vocab.ActivityType, excludeIRIs []*url.URL) error {
	logger.Debugf("[%s] Handling broadcast for activity [%s]", h.ServiceName, activity.ID())

	if err := h.storeActivity(activity); err != nil {
		return fmt.Errorf("store activity: %w", err)
	}

	if err := h.activityHandler.HandleActivity(nil, activity); err != nil {
		return fmt.Errorf("handle activity: %w", err)
	}

	for _, r := range h.resolveInboxes(activity.To(), excludeIRIs) {
		switch {
		case r.err == nil:
			if err := h.publishDeliverMessage(activity, r.iri); err != nil {
				// Return with an error since the only time publishToTarget returns an error is if
				// there's something wrong with the local server. (Maybe it's being shut down.)
				return fmt.Errorf("unable to publish activity to inbox %s: %w", r.iri, err)
			}
		case orberrors.IsTransient(r.err):
			logger.Warnf("Transient error resolving inbox %s: %s. IRI will be retried.", r.iri, r.err)

			if err := h.publishResolveAndDeliverMessage(activity, r.iri, excludeIRIs); err != nil {
				return fmt.Errorf("unable to publish activity for resolve %s: %w", r.iri, err)
			}
		default:
			logger.Errorf("Persistent error resolving inbox %s: %s. IRI will be ignored.", r.iri, r.err)
		}
	}

	return nil
}

func (h *Outbox) handleResolveIRIs(activity *vocab.ActivityType, toIRI *url.URL, excludeIRIs []*url.URL) error {
	logger.Debugf("[%s] Resolving inboxes from [%s] for activity [%s]", h.ServiceName, toIRI, activity.ID())

	for _, r := range h.resolveInboxes([]*url.URL{toIRI}, excludeIRIs) {
		if r.err != nil {
			logger.Warnf("Error resolving inbox %s: %s. Transient error: %t",
				r.iri, r.err, orberrors.IsTransient(r.err))

			return fmt.Errorf("resolve inbox [%s]: %w", r.iri, r.err)
		}

		if err := h.publishDeliverMessage(activity, r.iri); err != nil {
			// Return with an error since the only time publishToTarget returns an error is if
			// there's something wrong with the local server. (Maybe it's being shut down.)
			return fmt.Errorf("unable to publish activity to inbox %s: %w", r.iri, err)
		}
	}

	return nil
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

func (h *Outbox) publishBroadcastMessage(activity *vocab.ActivityType, excludeIRIs []*url.URL) error {
	activityMsg := &activityMessage{
		Type:        broadcastType,
		Activity:    activity,
		ExcludeIRIs: vocab.NewURLCollectionProperty(excludeIRIs...),
	}

	msgBytes, err := h.jsonMarshal(activityMsg)
	if err != nil {
		return orberrors.NewBadRequest(fmt.Errorf("marshal: %w", err))
	}

	msg := message.NewMessage(watermill.NewUUID(), msgBytes)

	logger.Debugf("[%s] Publishing activity message [%s] for activity [%s] to queue [%s]",
		h.ServiceName, msg.UUID, activity.ID(), h.Topic)

	return h.publisher.Publish(h.Topic, msg)
}

func (h *Outbox) publishResolveAndDeliverMessage(activity *vocab.ActivityType, targetIRI *url.URL,
	excludeIRIs []*url.URL) error {
	activityMsg := &activityMessage{
		Type:        resolveAndDeliverType,
		Activity:    activity,
		TargetIRI:   vocab.NewURLProperty(targetIRI),
		ExcludeIRIs: vocab.NewURLCollectionProperty(excludeIRIs...),
	}

	msgBytes, err := h.jsonMarshal(activityMsg)
	if err != nil {
		return orberrors.NewBadRequest(fmt.Errorf("marshal: %w", err))
	}

	msg := message.NewMessage(watermill.NewUUID(), msgBytes)

	logger.Debugf("[%s] Publishing 'resolve-and-deliver' message [%s] for activity [%s] to queue [%s]",
		h.ServiceName, msg.UUID, activity.ID(), h.Topic)

	return h.publisher.Publish(h.Topic, msg)
}

func (h *Outbox) publishDeliverMessage(activity *vocab.ActivityType, target *url.URL) error {
	activityMsg := &activityMessage{
		Type:      deliverType,
		Activity:  activity,
		TargetIRI: vocab.NewURLProperty(target),
	}

	msgBytes, err := h.jsonMarshal(activityMsg)
	if err != nil {
		return orberrors.NewBadRequest(fmt.Errorf("marshal: %w", err))
	}

	msg := message.NewMessage(watermill.NewUUID(), msgBytes)

	logger.Debugf("[%s] Publishing 'deliver' message [%s] for activity [%s] to queue [%s] with target [%s]",
		h.ServiceName, msg.UUID, activity.ID(), h.Topic, target)

	return h.publisher.Publish(h.Topic, msg)
}

func (h *Outbox) resolveInboxes(toIRIs, excludeIRIs []*url.URL) []*resolveIRIResponse {
	startTime := time.Now()

	defer func() {
		h.metrics.OutboxResolveInboxesTime(time.Since(startTime))
	}()

	var responses []*resolveIRIResponse

	var actorIRIs []*url.URL

	for _, r := range h.resolveIRIs(toIRIs, h.resolveActorIRIs) {
		if r.err != nil {
			responses = append(responses, r)
		} else {
			actorIRIs = append(actorIRIs, r.iri)
		}
	}

	return append(responses, h.resolveIRIs(
		deduplicateAndFilter(actorIRIs, excludeIRIs),
		func(iri *url.URL) []*resolveIRIResponse {
			inboxIRI, err := h.resolveInbox(iri)
			if err != nil {
				return []*resolveIRIResponse{{iri: iri, err: err}}
			}

			return []*resolveIRIResponse{{iri: inboxIRI}}
		},
	)...)
}

func (h *Outbox) resolveInbox(iri *url.URL) (*url.URL, error) {
	logger.Debugf("[%s] Retrieving actor from %s", h.ServiceName, iri)

	actor, err := h.client.GetActor(iri)
	if err != nil {
		return nil, err
	}

	return actor.Inbox(), nil
}

func (h *Outbox) resolveActorIRIs(iri *url.URL) []*resolveIRIResponse {
	if iri.String() == vocab.PublicIRI.String() {
		// Should not attempt to publishToTarget to the 'Public' URI.
		logger.Debugf("[%s] Not adding %s to recipients list", h.ServiceName, iri)

		return nil
	}

	return h.doResolveActorIRIs(iri)
}

func (h *Outbox) doResolveActorIRIs(iri *url.URL) []*resolveIRIResponse {
	logger.Debugf("[%s] Resolving IRI(s) for [%s]", h.ServiceName, iri)

	switch {
	case iri.String() == h.followersPath:
		responses, err := h.resolveReferences(store.Follower)
		if err != nil {
			return []*resolveIRIResponse{{iri: iri, err: err}}
		}

		return responses
	case iri.String() == h.witnessesPath:
		responses, err := h.resolveReferences(store.Witness)
		if err != nil {
			return []*resolveIRIResponse{{iri: iri, err: err}}
		}

		return responses
	default:
		resolvedIRIs, err := h.doResolveActorIRI(iri)
		if err != nil {
			return []*resolveIRIResponse{{iri: iri, err: err}}
		}

		var responses []*resolveIRIResponse

		for _, r := range resolvedIRIs {
			if strings.HasPrefix(r.String(), h.ServiceEndpointURL.String()) {
				// Ignore local endpoint.
				continue
			}

			responses = append(responses, &resolveIRIResponse{iri: r})
		}

		return responses
	}
}

type resolveIRIResponse struct {
	iri *url.URL
	err error
}

func (h *Outbox) resolveReferences(refType store.ReferenceType) ([]*resolveIRIResponse, error) {
	refs, err := h.loadReferences(refType)
	if err != nil {
		return nil, err
	}

	return h.resolveIRIs(refs, func(iri *url.URL) []*resolveIRIResponse {
		var responses []*resolveIRIResponse

		resolvedIRIs, err := h.doResolveActorIRI(iri)
		if err != nil {
			responses = append(responses, &resolveIRIResponse{iri: iri, err: err})
		} else {
			for _, r := range resolvedIRIs {
				responses = append(responses, &resolveIRIResponse{iri: r})
			}
		}

		return responses
	}), nil
}

func (h *Outbox) doResolveActorIRI(iri *url.URL) ([]*url.URL, error) {
	result, err := h.iriCache.Get(iri)
	if err != nil {
		logger.Debugf("[%s] Got error resolving IRI from cache for actor [%s]: %s", h.ServiceName, iri, err)

		return nil, err
	}

	return result.([]*url.URL), nil
}

func (h *Outbox) resolveActorIRI(iri *url.URL) ([]*url.URL, error) {
	// Resolve the actor IRI from .well-known.
	resolvedActorIRI, err := h.resourceResolver.ResolveHostMetaLink(iri.String(), discoveryrest.ActivityJSONType)
	if err != nil {
		return nil, fmt.Errorf("resolve actor [%s]: %w", iri, err)
	}

	logger.Debugf("[%s] Resolved IRI for actor [%s]: [%s]", h.ServiceName, iri, resolvedActorIRI)

	actorIRI, err := url.Parse(resolvedActorIRI)
	if err != nil {
		return nil, fmt.Errorf("parse actor URI: %w", err)
	}

	logger.Debugf("[%s] Sending request to %s to resolve recipient list", h.ServiceName, actorIRI)

	it, err := h.client.GetReferences(actorIRI)
	if err != nil {
		return nil, err
	}

	iris, err := client.ReadReferences(it, h.MaxRecipients)
	if err != nil {
		return nil, fmt.Errorf("read references for actor [%s]: %w", actorIRI, err)
	}

	return iris, nil
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
func (h *Outbox) resolveIRIs(toIRIs []*url.URL,
	resolve func(iri *url.URL) []*resolveIRIResponse) []*resolveIRIResponse {
	var wg sync.WaitGroup

	var responses []*resolveIRIResponse

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

				response := resolve(toIRI)

				mutex.Lock()
				responses = append(responses, response...)
				mutex.Unlock()
			}(reqIRI)
		}
	}()

	wg.Wait()

	close(resolveChan)

	return responses
}

func (h *Outbox) newActivityID() *url.URL {
	id, err := url.Parse(fmt.Sprintf("%s/activities/%s", h.ServiceEndpointURL, uuid.New()))
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

func (h *Outbox) sendActivity(activity *vocab.ActivityType, target *url.URL) error {
	logger.Debugf("[%s] Sending activity [%s] to target [%s]", h.ServiceName, activity.ID(), target)

	activityBytes, err := h.jsonMarshal(activity)
	if err != nil {
		return fmt.Errorf("marshal activity: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), activityBytes)

	req := transport.NewRequest(target,
		transport.WithHeader(transport.AcceptHeader, transport.ActivityStreamsContentType),
		transport.WithHeader(wmhttp.HeaderUUID, msg.UUID),
	)

	logger.Debugf("[%s] Sending message [%s] to [%s]: %s", h.ServiceName, msg.UUID, req.URL, msg.Payload)

	resp, err := h.httpTransport.Post(context.Background(), req, msg.Payload)
	if err != nil {
		return orberrors.NewTransientf("send message [%s]: %w", msg.UUID, err)
	}

	if err := resp.Body.Close(); err != nil {
		logger.Warnf("[%s] Error closing response body: %s", h.ServiceName, err)
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		logger.Debugf("[%s] Error code %d received in response from [%s] for message [%s]",
			h.ServiceName, resp.StatusCode, req.URL, msg.UUID)

		return orberrors.NewTransientf("server responded with error %d - %s", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		logger.Debugf("[%s] Error code %d received in response from [%s] for message [%s]",
			h.ServiceName, resp.StatusCode, req.URL, msg.UUID)

		return fmt.Errorf("server responded with error %d - %s", resp.StatusCode, resp.Status)
	}

	logger.Debugf("[%s] Message successfully sent [%s] to [%s] ", h.ServiceName, msg.UUID, req.URL)

	return nil
}

func populateConfigDefaults(cnfg *Config) Config {
	cfg := *cnfg

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = defaultConcurrentHTTPRequests
	}

	if cfg.CacheSize == 0 {
		cfg.CacheSize = defaultCacheSize
	}

	if cfg.CacheExpiration == 0 {
		cfg.CacheExpiration = defaultCacheExpiration
	}

	if cfg.SubscriberPoolSize == 0 {
		cfg.SubscriberPoolSize = defaultSubscriberPoolSize
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

func contains(arr []*url.URL, u *url.URL) bool {
	for _, s := range arr {
		if s.String() == u.String() {
			return true
		}
	}

	return false
}
