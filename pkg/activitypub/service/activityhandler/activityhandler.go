/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

const (
	defaultBufferSize      = 100
	defaultMaxWitnessDelay = 10 * time.Minute
)

// Config holds the configuration parameters for the activity handler.
type Config struct {
	// ServiceName is the name of the service (used for logging).
	ServiceName string

	// ServiceIRI is the IRI of the local service (actor). It is used as the 'actor' in activities
	// that are posted to the outbox by the handler.
	ServiceIRI *url.URL

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int

	// MaxWitnessDelay is the maximum delay from when the witness receives the transaction (via an Offer) for
	// the witness to include the transaction into the ledger.
	MaxWitnessDelay time.Duration
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
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
	client      activityPubClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New returns a new ActivityPub activity handler.
func New(cfg *Config, s store.Store, outbox service.Outbox, httpClient httpClient,
	opts ...service.HandlerOpt) *Handler {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	if cfg.MaxWitnessDelay == 0 {
		cfg.MaxWitnessDelay = defaultMaxWitnessDelay
	}

	h := &Handler{
		Config:   cfg,
		Handlers: options,
		store:    s,
		outbox:   outbox,
		client:   client.New(httpClient),
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
	case typeProp.Is(vocab.TypeOffer):
		return h.handleOfferActivity(activity)
	case typeProp.Is(vocab.TypeLike):
		return h.handleLikeActivity(activity)
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
		logger.Infof("[%s] Request for %s to follow %s has been accepted", h.ServiceName, h.ServiceIRI, actor.ID())

		return h.acceptActor(follow, actor)
	}

	logger.Infof("[%s] Request for %s to follow %s has been rejected. Replying with 'Reject' activity",
		h.ServiceName, actorIRI, h.ServiceIRI)

	return h.postRejectFollow(follow, actorIRI)
}

func (h *Handler) acceptActor(follow *vocab.ActivityType, actor *vocab.ActorType) error {
	if err := h.store.AddReference(store.Follower, h.ServiceIRI, actor.ID().URL()); err != nil {
		return fmt.Errorf("unable to store new follower: %w", err)
	}

	if err := h.store.PutActor(actor); err != nil {
		logger.Warnf("[%s] Unable to store actor %s: %s", actor.ID(), err)
	}

	logger.Infof("[%s] Replying to %s with 'Accept' activity", h.ServiceName, actor.ID())

	return h.postAcceptFollow(follow, actor.ID().URL())
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

func (h *Handler) hasFollower(actorIRI *url.URL) (bool, error) {
	it, err := h.store.QueryReferences(store.Follower,
		store.NewCriteria(
			store.WithObjectIRI(h.ServiceIRI),
			store.WithReferenceIRI(actorIRI),
		),
	)
	if err != nil {
		return false, fmt.Errorf("unable to retrieve existing follower: %w", err)
	}

	defer it.Close()

	return it.TotalItems() > 0, nil
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

func (h *Handler) handleOfferActivity(offer *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Offer' activity: %s", h.ServiceName, offer.ID())

	err := h.validateOfferActivity(offer)
	if err != nil {
		return fmt.Errorf("invalid 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	if time.Now().After(*offer.EndTime()) {
		return fmt.Errorf("offer [%s] has expired", offer.ID())
	}

	anchorCred := offer.Object().Object()

	result, err := h.witnessAnchorCredential(anchorCred)
	if err != nil {
		return fmt.Errorf("error creating result for 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	startTime := time.Now()
	endTime := startTime.Add(h.MaxWitnessDelay)

	like := vocab.NewLikeActivity(h.newActivityID(),
		vocab.NewObjectProperty(vocab.WithIRI(anchorCred.ID().URL())),
		vocab.WithActor(h.ServiceIRI),
		vocab.WithTo(offer.Actor()),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
	)

	err = h.store.AddReference(store.Liked, h.ServiceIRI, like.ID().URL())
	if err != nil {
		return fmt.Errorf("unable to store 'Like' activity for offer [%s]: %w", offer.ID(), err)
	}

	err = h.outbox.Post(like)
	if err != nil {
		return fmt.Errorf("unable to reply with 'Like' to %s for offer [%s]: %w", offer.Actor(), offer.ID(), err)
	}

	h.notify(offer)

	return nil
}

func (h *Handler) handleLikeActivity(like *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Like' activity: %s", h.ServiceName, like.ID())

	err := h.validateLikeActivity(like)
	if err != nil {
		return fmt.Errorf("invalid 'Like' activity [%s]: %w", like.ID(), err)
	}

	resultBytes, err := json.Marshal(like.Result().Object())
	if err != nil {
		return fmt.Errorf("marshal error of result in 'Like' activity [%s]: %w", like.ID(), err)
	}

	err = h.ProofHandler.HandleProof(like.Object().IRI().String(), *like.EndTime(), *like.StartTime(), resultBytes)
	if err != nil {
		return fmt.Errorf("proof handler returned error for 'Like' activity [%s]: %w", like.ID(), err)
	}

	err = h.store.AddReference(store.Like, h.ServiceIRI, like.ID().URL())
	if err != nil {
		return fmt.Errorf("unable to store 'Like' activity [%s]: %w", like.ID(), err)
	}

	h.notify(like)

	return nil
}

func (h *Handler) handleAnchorCredential(target *vocab.ObjectProperty, obj *vocab.ObjectType) error {
	if !target.Type().Is(vocab.TypeContentAddressedStorage) {
		return fmt.Errorf("unsupported target type %s", target.Type().Types())
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	return h.AnchorCredentialHandler.HandlerAnchorCredential(target.Object().ID().String(), bytes)
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
	it, err := h.store.QueryReferences(store.Follower, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
	if err != nil {
		return err
	}

	defer it.Close()

	followers, err := storeutil.ReadReferences(it, -1)
	if err != nil {
		return err
	}

	if len(followers) == 0 {
		logger.Infof("[%s] No followers to announce 'Create' to", h.ServiceIRI)

		return nil
	}

	ref, err := newAnchorCredentialReferenceFromCreate(create)
	if err != nil {
		return err
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

	logger.Debugf("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, followers)

	err = h.outbox.Post(announce)
	if err != nil {
		return err
	}

	logger.Debugf("[%s] Adding 'Announce' %s to shares of %s", h.ServiceIRI, announce.ID(), ref.ID())

	err = h.store.AddReference(store.Share, ref.ID().URL(), announce.ID().URL())
	if err != nil {
		logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of %s",
			h.ServiceIRI, announce.ID(), ref.ID())
	}

	return nil
}

func (h *Handler) announceAnchorCredentialRef(ref *vocab.AnchorCredentialReferenceType) error {
	it, err := h.store.QueryReferences(store.Follower, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
	if err != nil {
		return err
	}

	defer it.Close()

	followers, err := storeutil.ReadReferences(it, -1)
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

	logger.Debugf("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, followers)

	err = h.outbox.Post(announce)
	if err != nil {
		return err
	}

	anchorCredID := ref.Target().Object().ID()

	logger.Debugf("[%s] Adding 'Announce' %s to shares of %s", h.ServiceIRI, announce.ID(), anchorCredID)

	err = h.store.AddReference(store.Share, anchorCredID.URL(), announce.ID().URL())
	if err != nil {
		logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of %s", h.ServiceIRI, announce.ID(), anchorCredID)
	}

	return nil
}

func (h *Handler) notify(activity *vocab.ActivityType) {
	h.mutex.RLock()
	subscribers := h.subscribers
	h.mutex.RUnlock()

	for _, ch := range subscribers {
		ch <- activity
	}
}

func (h *Handler) validateOfferActivity(offer *vocab.ActivityType) error {
	if offer.StartTime() == nil {
		return fmt.Errorf("startTime is required")
	}

	if offer.EndTime() == nil {
		return fmt.Errorf("endTime is required")
	}

	obj := offer.Object().Object()

	if obj == nil {
		return fmt.Errorf("object is required")
	}

	if !obj.Type().Is(vocab.TypeAnchorCredential, vocab.TypeVerifiableCredential) {
		return fmt.Errorf("unsupported object type in Offer activity %s", obj.Type())
	}

	return nil
}

func (h *Handler) validateLikeActivity(like *vocab.ActivityType) error {
	if like.StartTime() == nil {
		return fmt.Errorf("startTime is required")
	}

	if like.EndTime() == nil {
		return fmt.Errorf("endTime is required")
	}

	if like.Object().IRI() == nil {
		return fmt.Errorf("object is required")
	}

	if like.Result() == nil {
		return fmt.Errorf("result is required")
	}

	return nil
}

func (h *Handler) witnessAnchorCredential(anchorCred *vocab.ObjectType) (*vocab.ObjectType, error) {
	bytes, err := json.Marshal(anchorCred)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal object in 'Offer' activity: %w", err)
	}

	response, err := h.Witness.Witness(bytes)
	if err != nil {
		return nil, err
	}

	proof, err := vocab.UnmarshalToDoc(response)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal proof: %w", err)
	}

	result, err := vocab.NewObjectWithDocument(proof)
	if err != nil {
		return nil, fmt.Errorf("error creating offer result: %w", err)
	}

	return result, nil
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		AnchorCredentialHandler: &noOpAnchorCredentialPublisher{},
		FollowerAuth:            &acceptAllFollowerAuth{},
		ProofHandler:            &noOpProofHandler{},
	}
}

func (h *Handler) newActivityID() *url.URL {
	id, err := url.Parse(fmt.Sprintf("%s/%s", h.ServiceIRI.String(), uuid.New()))
	if err != nil {
		// Should never happen since we've already validated the URLs
		panic(err)
	}

	return id
}

func (h *Handler) resolveActor(iri *url.URL) (*vocab.ActorType, error) {
	actor, err := h.store.GetActor(iri)
	if err == nil {
		return actor, nil
	}

	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// The actor isn't in our local store. Retrieve the actor from the remote server.
	return h.client.GetActor(iri)
}

func newAnchorCredentialReferenceFromCreate(create *vocab.ActivityType) (*vocab.AnchorCredentialReferenceType, error) {
	anchorCredential := create.Object().Object()

	anchorCredentialBytes, err := json.Marshal(anchorCredential)
	if err != nil {
		return nil, err
	}

	anchorCredDoc, err := vocab.UnmarshalToDoc(anchorCredentialBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal anchor credential: %w", err)
	}

	targetObj := create.Target().Object()

	return vocab.NewAnchorCredentialReferenceWithDocument(anchorCredential.ID().URL(),
		targetObj.ID().URL(), targetObj.CID(), anchorCredDoc)
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

type noOpProofHandler struct {
}

func (p *noOpProofHandler) HandleProof(anchorCredID string, startTime, endTime time.Time, proof []byte) error {
	return nil
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
			return true
		}
	}

	return false
}
