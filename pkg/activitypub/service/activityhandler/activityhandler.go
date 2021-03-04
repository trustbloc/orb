/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

const defaultBufferSize = 100

// Config holds the configuration parameters for the activity handler.
type Config struct {
	// ServiceName is the name of the service (used for logging).
	ServiceName string

	// ServiceIRI is the IRI of the local service (actor). It is used as the 'actor' in activities
	// that are posted to the outbox by the handler.
	ServiceIRI *url.URL

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int
}

// Handler provides an implementation for the ActivityHandler interface.
type Handler struct {
	*Config
	*lifecycle.Lifecycle
	*service.Handlers

	store       store.Store
	outbox      service.Outbox
	mutex       sync.RWMutex
	subscribers []chan *vocab.ActivityType
}

// New returns a new ActivityPub activity handler.
func New(cfg *Config, s store.Store, outbox service.Outbox, opts ...service.HandlerOpt) *Handler {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	h := &Handler{
		Config:   cfg,
		Handlers: options,
		store:    s,
		outbox:   outbox,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName, lifecycle.WithStop(h.stop))

	return h
}

func (h *Handler) stop() {
	logger.Infof("[%s] Stopping activity handler", h.ServiceName)

	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, ch := range h.subscribers {
		close(ch)
	}

	h.subscribers = nil
}

// Subscribe allows a client to receive published activities.
func (h *Handler) Subscribe() <-chan *vocab.ActivityType {
	ch := make(chan *vocab.ActivityType, h.BufferSize)

	h.mutex.Lock()
	h.subscribers = append(h.subscribers, ch)
	h.mutex.Unlock()

	return ch
}

// HandleActivity handles the ActivityPub activity.
func (h *Handler) HandleActivity(activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.handleCreateActivity(activity)
	case typeProp.Is(vocab.TypeFollow):
		return h.handleFollowActivity(activity)
	case typeProp.Is(vocab.TypeAccept):
		return h.handleAcceptActivity(activity)
	case typeProp.Is(vocab.TypeReject):
		return h.handleRejectActivity(activity)
	case typeProp.Is(vocab.TypeAnnounce):
		return h.handleAnnounceActivity(activity)
	default:
		return fmt.Errorf("unsupported activity type: %s", typeProp.Types())
	}
}

func (h *Handler) handleCreateActivity(create *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Create' activity: %s", h.ServiceName, create.ID())

	obj := create.Object()

	t := obj.Type()

	switch {
	case t.Is(vocab.TypeAnchorCredential, vocab.TypeVerifiableCredential):
		if err := h.handleAnchorCredential(create.Target(), obj.Object()); err != nil {
			return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
		}

		if err := h.announceAnchorCredential(create); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' to our followers: %s", h.ServiceIRI, err)
		}

	case t.Is(vocab.TypeAnchorCredentialRef):
		ref := obj.AnchorCredentialReference()

		if err := h.handleAnchorCredential(ref.Target(), ref.Object().Object()); err != nil {
			return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
		}

		if err := h.announceAnchorCredentialRef(ref); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' to our followers: %s", h.ServiceIRI, err)
		}

	default:
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", t, create.ID())
	}

	h.notify(create)

	return nil
}

func (h *Handler) handleFollowActivity(follow *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Follow' activity: %s", h.ServiceName, follow.ID())

	actorIRI := follow.Actor()
	if actorIRI == nil {
		return fmt.Errorf("no actor specified in 'Follow' activity")
	}

	iri := follow.Object().IRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in 'object' field of the 'Follow' activity")
	}

	// Make sure that the IRI is targeting this service. If not then ignore the message
	if iri.String() != h.ServiceIRI.String() {
		logger.Infof("[%s] Not handling 'Follow' activity %s since this service %s is not the target object %s",
			h.ServiceName, follow.ID(), iri, h.ServiceIRI)

		return nil
	}

	hasFollower, err := h.hasFollower(actorIRI)
	if err != nil {
		return err
	}

	if hasFollower {
		logger.Infof("[%s] Actor %s is already following %s. Replying with 'Accept' activity.",
			h.ServiceName, actorIRI, h.ServiceIRI)

		return h.postAcceptFollow(follow, actorIRI)
	}

	actor, err := h.resolveActor(actorIRI)
	if err != nil {
		return fmt.Errorf("unable to retrieve actor [%s]: %w", actorIRI, err)
	}

	accept, err := h.FollowerAuth.AuthorizeFollower(actor)
	if err != nil {
		return fmt.Errorf("unable to authorize follower [%s]: %w", actorIRI, err)
	}

	if accept {
		if err := h.store.AddReference(store.Follower, iri, actorIRI); err != nil {
			return fmt.Errorf("unable to store new follower: %w", err)
		}

		logger.Infof("[%s] Request for %s to follow %s has been accepted. Replying with 'Accept' activity",
			h.ServiceName, iri, actorIRI)

		return h.postAcceptFollow(follow, actorIRI)
	}

	logger.Infof("[%s] Request for %s to follow %s has been rejected. Replying with 'Reject' activity",
		h.ServiceName, actorIRI, h.ServiceIRI)

	return h.postRejectFollow(follow, actorIRI)
}

func (h *Handler) handleAcceptActivity(accept *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Accept' activity: %s", h.ServiceName, accept.ID())

	actor := accept.Actor()
	if actor == nil {
		return fmt.Errorf("no actor specified in 'Accept' activity")
	}

	follow := accept.Object().Activity()
	if follow == nil {
		return fmt.Errorf("no 'Follow' activity specified in the 'object' field of the 'Accept' activity")
	}

	if !follow.Type().Is(vocab.TypeFollow) {
		return fmt.Errorf("the 'object' field of the 'Accept' activity must be a 'Follow' type")
	}

	iri := follow.Actor()
	if iri == nil {
		return fmt.Errorf("no actor specified in the original 'Follow' activity of the 'Accept' activity")
	}

	// Make sure that the actor in the original 'Follow' activity is this service.
	// If not then we can ignore the message.
	if iri.String() != h.ServiceIRI.String() {
		logger.Infof(
			"[%s] Not handling 'Accept' %s since the actor %s in the 'Follow' activity is not this service %s",
			h.ServiceName, accept.ID(), iri, h.ServiceIRI)

		return nil
	}

	if err := h.store.AddReference(store.Following, h.ServiceIRI, actor); err != nil {
		return fmt.Errorf("unable to store new following: %w", err)
	}

	logger.Debugf("[%s] %s is now a follower of %s", h.ServiceName, h.ServiceIRI, actor)

	h.notify(accept)

	return nil
}

func (h *Handler) handleRejectActivity(reject *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Reject' activity: %s", h.ServiceName, reject.ID())

	actor := reject.Actor()
	if actor == nil {
		return fmt.Errorf("no actor specified in 'Reject' activity")
	}

	follow := reject.Object().Activity()
	if follow == nil {
		return fmt.Errorf("no 'Follow' activity specified in the 'object' field of the 'Reject' activity")
	}

	if !follow.Type().Is(vocab.TypeFollow) {
		return fmt.Errorf("the 'object' field of the 'Reject' activity must be a 'Follow' type")
	}

	iri := follow.Actor()
	if iri == nil {
		return fmt.Errorf("no actor specified in the original 'Follow' activity of the 'Reject' activity")
	}

	// Make sure that the actor in the original 'Follow' activity is this service. If not then we can ignore the message.
	if iri.String() != h.ServiceIRI.String() {
		logger.Infof(
			"[%s] Not handling 'Reject' %s since the actor %s in the 'Follow' activity is not this service: %s",
			h.ServiceName, reject.ID(), iri, h.ServiceIRI)

		return nil
	}

	logger.Warnf("[%s] %s rejected our request to follow", h.ServiceName, iri)

	h.notify(reject)

	return nil
}

func (h *Handler) postAcceptFollow(follow *vocab.ActivityType, toIRI *url.URL) error {
	acceptActivity := vocab.NewAcceptActivity(h.newActivityID(),
		vocab.NewObjectProperty(vocab.WithActivity(follow)),
		vocab.WithActor(h.ServiceIRI),
		vocab.WithTo(toIRI),
	)

	h.notify(follow)

	logger.Debugf("[%s] Publishing 'Accept' activity to %s", h.ServiceName, toIRI)

	if err := h.outbox.Post(acceptActivity); err != nil {
		return fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err)
	}

	return nil
}

func (h *Handler) postRejectFollow(follow *vocab.ActivityType, toIRI *url.URL) error {
	reject := vocab.NewRejectActivity(h.newActivityID(),
		vocab.NewObjectProperty(vocab.WithActivity(follow)),
		vocab.WithActor(h.ServiceIRI),
		vocab.WithTo(toIRI),
	)

	logger.Debugf("[%s] Publishing 'Reject' activity to %s", h.ServiceName, toIRI)

	if err := h.outbox.Post(reject); err != nil {
		return fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err)
	}

	return nil
}

func (h *Handler) hasFollower(actorIRI fmt.Stringer) (bool, error) {
	existingFollowers, err := h.store.GetReferences(store.Follower, h.ServiceIRI)
	if err != nil {
		return false, fmt.Errorf("unable to retrieve existing follower: %w", err)
	}

	return containsIRI(existingFollowers, actorIRI), nil
}

func (h *Handler) handleAnnounceActivity(announce *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Announce' activity: %s", h.ServiceName, announce.ID())

	obj := announce.Object()

	t := obj.Type()

	switch {
	case t.Is(vocab.TypeCollection):
		if err := h.handleAnnounceCollection(obj.Collection().Items()); err != nil {
			return fmt.Errorf("error handling 'Announce' activity [%s]: %w", announce.ID(), err)
		}

	case t.Is(vocab.TypeOrderedCollection):
		if err := h.handleAnnounceCollection(obj.OrderedCollection().Items()); err != nil {
			return fmt.Errorf("error handling 'Announce' activity [%s]: %w", announce.ID(), err)
		}

	default:
		return fmt.Errorf("unsupported object type for 'Announce' %s", t)
	}

	h.notify(announce)

	return nil
}

func (h *Handler) handleAnchorCredential(target *vocab.ObjectProperty, obj *vocab.ObjectType) error {
	if !target.Type().Is(vocab.TypeCAS) {
		return fmt.Errorf("unsupported target type %s", target.Type().Types())
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	return h.AnchorCredentialHandler.HandlerAnchorCredential(target.Object().ID(), bytes)
}

func (h *Handler) handleAnnounceCollection(items []*vocab.ObjectProperty) error {
	logger.Infof("[%s] Handling announce collection. Items: %+v\n", h.ServiceIRI, items)

	for _, item := range items {
		if !item.Type().Is(vocab.TypeAnchorCredentialRef) {
			return fmt.Errorf("expecting 'AnchorCredentialReference' type")
		}

		ref := item.AnchorCredentialReference()
		if err := h.handleAnchorCredential(ref.Target(), ref.Object().Object()); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) announceAnchorCredential(create *vocab.ActivityType) error {
	followers, err := h.store.GetReferences(store.Follower, h.ServiceIRI)
	if err != nil {
		return err
	}

	if len(followers) == 0 {
		logger.Infof("[%s] No followers to announce 'Create' to", h.ServiceIRI)

		return nil
	}

	anchorCredential := create.Object().Object()

	anchorCredentialBytes, err := json.Marshal(anchorCredential)
	if err != nil {
		return err
	}

	published := time.Now()

	ref, err := vocab.NewAnchorCredentialReferenceWithDocument(anchorCredential.ID(),
		create.Target().Object().ID(), vocab.MustUnmarshalToDoc(anchorCredentialBytes),
	)
	if err != nil {
		return err
	}

	announce := vocab.NewAnnounceActivity(h.newActivityID(),
		vocab.NewObjectProperty(
			vocab.WithCollection(
				vocab.NewCollection(
					[]*vocab.ObjectProperty{
						vocab.NewObjectProperty(
							vocab.WithAnchorCredentialReference(ref),
						),
					},
				),
			),
		),
		vocab.WithActor(h.ServiceIRI),
		vocab.WithTo(followers...),
		vocab.WithPublishedTime(&published),
	)

	logger.Infof("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, followers)

	return h.outbox.Post(announce)
}

func (h *Handler) announceAnchorCredentialRef(ref *vocab.AnchorCredentialReferenceType) error {
	followers, err := h.store.GetReferences(store.Follower, h.ServiceIRI)
	if err != nil {
		return err
	}

	if len(followers) == 0 {
		logger.Infof("[%s] No followers to announce 'Create' to", h.ServiceIRI)

		return nil
	}

	published := time.Now()

	announce := vocab.NewAnnounceActivity(h.newActivityID(),
		vocab.NewObjectProperty(
			vocab.WithCollection(
				vocab.NewCollection(
					[]*vocab.ObjectProperty{
						vocab.NewObjectProperty(
							vocab.WithAnchorCredentialReference(ref),
						),
					},
				),
			),
		),
		vocab.WithActor(h.ServiceIRI),
		vocab.WithTo(followers...),
		vocab.WithPublishedTime(&published),
	)

	logger.Infof("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, followers)

	return h.outbox.Post(announce)
}

func (h *Handler) notify(activity *vocab.ActivityType) {
	h.mutex.RLock()
	subscribers := h.subscribers
	h.mutex.RUnlock()

	for _, ch := range subscribers {
		ch <- activity
	}
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		AnchorCredentialHandler: &noOpAnchorCredentialPublisher{},
		FollowerAuth:            &acceptAllFollowerAuth{},
	}
}

func (h *Handler) newActivityID() string {
	return fmt.Sprintf("%s/%s", h.ServiceIRI.String(), uuid.New())
}

func (h *Handler) resolveActor(iri *url.URL) (*vocab.ActorType, error) {
	actor, err := h.store.GetActor(iri)
	if err == nil {
		return actor, nil
	}

	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// TODO: The actor isn't in our local store. Retrieve the actor from remote.
	return nil, store.ErrNotFound
}

type noOpAnchorCredentialPublisher struct {
}

func (p *noOpAnchorCredentialPublisher) HandlerAnchorCredential(string, []byte) error {
	return nil
}

type acceptAllFollowerAuth struct {
}

func (a *acceptAllFollowerAuth) AuthorizeFollower(*vocab.ActorType) (bool, error) {
	return true, nil
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
			return true
		}
	}

	return false
}
