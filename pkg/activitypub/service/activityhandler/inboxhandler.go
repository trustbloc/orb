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
	"time"

	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var errDuplicateAnchorCredential = errors.New("anchor credential already handled")

// Inbox handles activities posted to the inbox.
type Inbox struct {
	*handler
	*service.Handlers

	outbox service.Outbox
}

// NewInbox returns a new ActivityPub inbox activity handler.
func NewInbox(cfg *Config, s store.Store, outbox service.Outbox, t httpTransport,
	opts ...service.HandlerOpt) *Inbox {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	h := &Inbox{
		outbox:   outbox,
		Handlers: options,
	}

	h.handler = newHandler(cfg, s, t,
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Follower)
		},
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Witnessing)
		},
	)

	return h
}

// HandleActivity handles the ActivityPub activity in the inbox.
func (h *Inbox) HandleActivity(activity *vocab.ActivityType) error { //nolint: cyclop
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.handleCreateActivity(activity)
	case typeProp.Is(vocab.TypeFollow):
		return h.handleFollowActivity(activity)
	case typeProp.Is(vocab.TypeInviteWitness):
		return h.handleWitnessActivity(activity)
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
	case typeProp.Is(vocab.TypeUndo):
		return h.handleUndoActivity(activity)
	default:
		return fmt.Errorf("unsupported activity type: %s", typeProp.Types())
	}
}

func (h *Inbox) handleCreateActivity(create *vocab.ActivityType) error {
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

		if err := h.announceAnchorCredentialRef(create); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' to our followers: %s", h.ServiceIRI, err)
		}

	default:
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", t, create.ID())
	}

	h.notify(create)

	return nil
}

func (h *Inbox) handleReferenceActivity(activity *vocab.ActivityType, refType store.ReferenceType,
	auth service.ActorAuth) error {
	logger.Debugf("[%s] Handling '%s' activity: %s", h.ServiceName, activity.Type(), activity.ID())

	err := h.validateActivity(activity)
	if err != nil {
		return fmt.Errorf("validate '%s' activity [%s]: %w", activity.Type(), activity.ID(), err)
	}

	actorIRI := activity.Actor()

	hasRef, err := h.hasReference(h.ServiceIRI, actorIRI, refType)
	if err != nil {
		return err
	}

	if hasRef {
		logger.Infof("[%s] Actor %s already has %s in its %s collection. Replying with 'Accept' activity.",
			h.ServiceName, actorIRI, h.ServiceIRI, refType)

		return h.postAccept(activity, actorIRI)
	}

	actor, err := h.resolveActor(actorIRI)
	if err != nil {
		return fmt.Errorf("unable to retrieve actor [%s]: %w", actorIRI, err)
	}

	accept, err := auth.AuthorizeActor(actor)
	if err != nil {
		return fmt.Errorf("authorize actor [%s]: %w", actorIRI, err)
	}

	if accept {
		logger.Infof("[%s] Request for %s to activity %s has been accepted", h.ServiceName, h.ServiceIRI, actor.ID())

		return h.acceptActor(activity, actor, refType)
	}

	logger.Infof("[%s] Request for %s to activity %s has been rejected. Replying with 'Reject' activity",
		h.ServiceName, actorIRI, h.ServiceIRI)

	return h.postReject(activity, actorIRI)
}

func (h *Inbox) handleFollowActivity(follow *vocab.ActivityType) error {
	return h.handleReferenceActivity(follow, store.Follower, h.FollowerAuth)
}

func (h *Inbox) handleWitnessActivity(follow *vocab.ActivityType) error {
	return h.handleReferenceActivity(follow, store.Witnessing, h.WitnessInvitationAuth)
}

func (h *Inbox) validateActivity(activity *vocab.ActivityType) error {
	if activity.Actor() == nil {
		return fmt.Errorf("no actor specified")
	}

	iri := activity.Object().IRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in 'object' field")
	}

	// Make sure that the IRI is targeting this service. If not then ignore the message
	if iri.String() != h.ServiceIRI.String() {
		return fmt.Errorf("this service is not the target object for the '%s'", activity.Type())
	}

	return nil
}

func (h *Inbox) acceptActor(activity *vocab.ActivityType, actor *vocab.ActorType, refType store.ReferenceType) error {
	if err := h.store.AddReference(refType, h.ServiceIRI, actor.ID().URL()); err != nil {
		return fmt.Errorf("unable to store reference: %w", err)
	}

	if err := h.store.PutActor(actor); err != nil {
		logger.Warnf("[%s] Unable to store actor %s: %s", actor.ID(), err)
	}

	logger.Debugf("[%s] Replying to %s with 'Accept' activity", h.ServiceName, actor.ID())

	return h.postAccept(activity, actor.ID().URL())
}

func (h *Inbox) handleAcceptActivity(accept *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Accept' activity: %s", h.ServiceName, accept.ID())

	if err := h.validateAcceptRejectActivity(accept); err != nil {
		return err
	}

	activity := accept.Object().Activity()

	switch {
	case activity.Type().Is(vocab.TypeFollow):
		if err := h.handleAccept(accept, store.Following); err != nil {
			return fmt.Errorf("handle accept 'Follow' activity %s: %w", accept.ID(), err)
		}

	case activity.Type().Is(vocab.TypeInviteWitness):
		if err := h.handleAccept(accept, store.Witness); err != nil {
			return fmt.Errorf("handle accept 'InviteWitness' activity %s: %w", accept.ID(), err)
		}

	default:
		return fmt.Errorf("unsupported activity type [%s] in the 'object' field of the 'Accept' activity",
			activity.Type())
	}

	h.notify(accept)

	return nil
}

func (h *Inbox) handleAccept(accept *vocab.ActivityType, refType store.ReferenceType) error {
	exists, err := h.hasReference(h.ServiceIRI, accept.Actor(), refType)
	if err != nil {
		return fmt.Errorf("query '%s' for actor %s: %w", refType, accept.Actor(), err)
	}

	if exists {
		return fmt.Errorf("actor %s is already in the '%s' collection", accept.Actor(), refType)
	}

	err = h.store.AddReference(refType, h.ServiceIRI, accept.Actor())
	if err != nil {
		return fmt.Errorf("handle accept '%s' activity %s: %w", refType, accept.ID(), err)
	}

	return nil
}

func (h *Inbox) handleRejectActivity(reject *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Reject' activity: %s", h.ServiceName, reject.ID())

	if err := h.validateAcceptRejectActivity(reject); err != nil {
		return err
	}

	h.notify(reject)

	return nil
}

func (h *Inbox) validateAcceptRejectActivity(a *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling '%s' activity: %s", h.ServiceName, a.Type(), a.ID())

	if a.Actor() == nil {
		return fmt.Errorf("no actor specified in '%s' activity", a.Type())
	}

	activity := a.Object().Activity()
	if activity == nil {
		return fmt.Errorf("no activity specified in the 'object' field of the '%s' activity", a.Type())
	}

	if !activity.Type().IsAny(vocab.TypeFollow, vocab.TypeInviteWitness) {
		return fmt.Errorf("unsupported activity type [%s] in the 'object' field of the 'Accept' activity",
			activity.Type())
	}

	iri := activity.Actor()
	if iri == nil {
		return fmt.Errorf("no actor specified in the object of the '%s' activity", a.Type())
	}

	// Make sure that the actorIRI in the original activity is this service.
	if iri.String() != h.ServiceIRI.String() {
		return fmt.Errorf("the actor in the object of the '%s' activity is not this service", a.Type())
	}

	return nil
}

func (h *Inbox) postAccept(activity *vocab.ActivityType, toIRI *url.URL) error {
	acceptActivity := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(activity)),
		vocab.WithTo(toIRI),
	)

	h.notify(activity)

	logger.Debugf("[%s] Publishing 'Accept' activity to %s", h.ServiceName, toIRI)

	if _, err := h.outbox.Post(acceptActivity); err != nil {
		return fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err)
	}

	return nil
}

func (h *Inbox) postReject(activity *vocab.ActivityType, toIRI *url.URL) error {
	reject := vocab.NewRejectActivity(
		vocab.NewObjectProperty(vocab.WithActivity(activity)),
		vocab.WithTo(toIRI),
	)

	logger.Debugf("[%s] Publishing 'Reject' activity to %s", h.ServiceName, toIRI)

	if _, err := h.outbox.Post(reject); err != nil {
		return fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err)
	}

	return nil
}

func (h *Inbox) hasReference(objectIRI, refIRI *url.URL, refType store.ReferenceType) (bool, error) {
	it, err := h.store.QueryReferences(refType,
		store.NewCriteria(
			store.WithObjectIRI(objectIRI),
			store.WithReferenceIRI(refIRI),
		),
	)
	if err != nil {
		return false, fmt.Errorf("query references: %w", err)
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	_, err = it.Next()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("get next reference: %w", err)
	}

	return true, nil
}

func (h *Inbox) handleAnnounceActivity(announce *vocab.ActivityType) error {
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

func (h *Inbox) handleOfferActivity(offer *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Offer' activity: %s", h.ServiceName, offer.ID())

	err := h.validateOfferActivity(offer)
	if err != nil {
		return fmt.Errorf("invalid 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	isWitnessing, err := h.hasReference(h.ServiceIRI, offer.Actor(), store.Witnessing)
	if err != nil {
		return fmt.Errorf("retrieve reference: %w", err)
	}

	if !isWitnessing {
		return fmt.Errorf("not handling 'Offer' activity [%s] since [%s] is not in the 'witnessing' collection",
			offer.ID(), offer.Actor())
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

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(vocab.WithIRI(anchorCred.ID().URL())),
		vocab.WithTo(offer.Actor()),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
	)

	activityID, err := h.outbox.Post(like)
	if err != nil {
		return fmt.Errorf("unable to reply with 'Like' to %s for offer [%s]: %w", offer.Actor(), offer.ID(), err)
	}

	err = h.store.AddReference(store.Liked, h.ServiceIRI, activityID)
	if err != nil {
		return fmt.Errorf("unable to store 'Like' activity for offer [%s]: %w", offer.ID(), err)
	}

	h.notify(offer)

	return nil
}

func (h *Inbox) handleLikeActivity(like *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Like' activity: %s", h.ServiceName, like.ID())

	err := h.validateLikeActivity(like)
	if err != nil {
		return fmt.Errorf("invalid 'Like' activity [%s]: %w", like.ID(), err)
	}

	resultBytes, err := json.Marshal(like.Result().Object())
	if err != nil {
		return fmt.Errorf("marshal error of result in 'Like' activity [%s]: %w", like.ID(), err)
	}

	err = h.ProofHandler.HandleProof(like.Object().IRI().String(), *like.StartTime(), *like.EndTime(), resultBytes)
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

func (h *Inbox) handleAnchorCredential(target *vocab.ObjectProperty, obj *vocab.ObjectType) error {
	if !target.Type().Is(vocab.TypeContentAddressedStorage) {
		return fmt.Errorf("unsupported target type %s", target.Type().Types())
	}

	targetIRI := target.Object().ID().URL()

	ok, err := h.hasReference(targetIRI, h.ServiceIRI, store.AnchorCredential)
	if err != nil {
		return fmt.Errorf("has anchor credential [%s]: %w", targetIRI, err)
	}

	if ok {
		return fmt.Errorf("handle anchor credential [%s]: %w", targetIRI, errDuplicateAnchorCredential)
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	err = h.AnchorCredentialHandler.HandleAnchorCredential(targetIRI, target.Object().CID(), bytes)
	if err != nil {
		return fmt.Errorf("handler anchor credential: %w", err)
	}

	logger.Debugf("[%s] Storing anchor credential reference [%s]", h.ServiceName, targetIRI)

	err = h.store.AddReference(store.AnchorCredential, targetIRI, h.ServiceIRI)
	if err != nil {
		return fmt.Errorf("store anchor credential reference: %w", err)
	}

	return nil
}

func (h *Inbox) handleAnnounceCollection(items []*vocab.ObjectProperty) error {
	logger.Infof("[%s] Handling announce collection. Items: %+v\n", h.ServiceIRI, items)

	for _, item := range items {
		if !item.Type().Is(vocab.TypeAnchorCredentialRef) {
			return fmt.Errorf("expecting 'AnchorCredentialReference' type")
		}

		ref := item.AnchorCredentialReference()
		if err := h.handleAnchorCredential(ref.Target(), ref.Object().Object()); err != nil {
			// Continue processing other anchor credentials on duplicate error.
			if !errors.Is(err, errDuplicateAnchorCredential) {
				return err
			}
		}
	}

	return nil
}

func (h *Inbox) announceAnchorCredential(create *vocab.ActivityType) error {
	announceTo, err := h.getAnnounceToList(create)
	if err != nil {
		return fmt.Errorf("announce anchor credential: %w", err)
	}

	if len(announceTo) == 0 {
		logger.Debugf("[%s] No followers to announce 'Create' to", h.ServiceIRI)

		return nil
	}

	ref, err := newAnchorCredentialReferenceFromCreate(create)
	if err != nil {
		return err
	}

	published := time.Now()

	announce := vocab.NewAnnounceActivity(
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
		vocab.WithTo(announceTo...),
		vocab.WithPublishedTime(&published),
	)

	logger.Debugf("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, announceTo)

	activityID, err := h.outbox.Post(announce)
	if err != nil {
		return err
	}

	logger.Debugf("[%s] Adding 'Announce' %s to shares of %s", h.ServiceIRI, announce.ID(), ref.ID())

	err = h.store.AddReference(store.Share, ref.ID().URL(), activityID)
	if err != nil {
		logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of %s: %s",
			h.ServiceIRI, announce.ID(), ref.ID(), err)
	}

	return nil
}

func (h *Inbox) announceAnchorCredentialRef(create *vocab.ActivityType) error {
	announceTo, err := h.getAnnounceToList(create)
	if err != nil {
		return fmt.Errorf("announce anchor credential: %w", err)
	}

	if len(announceTo) == 0 {
		logger.Debugf("[%s] No followers to announce 'Create' to", h.ServiceIRI)

		return nil
	}

	ref := create.Object().AnchorCredentialReference()

	published := time.Now()

	announce := vocab.NewAnnounceActivity(
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
		vocab.WithTo(announceTo...),
		vocab.WithPublishedTime(&published),
	)

	logger.Debugf("[%s] Posting 'Announce' to followers %s", h.ServiceIRI, announceTo)

	activityID, err := h.outbox.Post(announce)
	if err != nil {
		return err
	}

	anchorCredID := ref.Target().Object().ID()

	logger.Debugf("[%s] Adding 'Announce' %s to shares of %s", h.ServiceIRI, announce.ID(), anchorCredID)

	err = h.store.AddReference(store.Share, anchorCredID.URL(), activityID)
	if err != nil {
		logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of %s",
			h.ServiceIRI, announce.ID(), anchorCredID)
	}

	return nil
}

func (h *Inbox) validateOfferActivity(offer *vocab.ActivityType) error {
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

func (h *Inbox) validateLikeActivity(like *vocab.ActivityType) error {
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

func (h *Inbox) witnessAnchorCredential(anchorCred *vocab.ObjectType) (*vocab.ObjectType, error) {
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

func (h *Inbox) undoAddReference(activity *vocab.ActivityType, refType store.ReferenceType) error {
	iri := activity.Object().IRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in 'object' field of the '%s' activity", activity.Type())
	}

	// Make sure that the IRI is targeting this service. If not then ignore the message.
	if iri.String() != h.ServiceIRI.String() {
		return fmt.Errorf("this service is not the target for the 'Undo'")
	}

	actorIRI := activity.Actor()

	err := h.store.DeleteReference(refType, h.ServiceIRI, actorIRI)
	if err != nil {
		return fmt.Errorf("unable to delete %s from %s's collection of %s", actorIRI, h.ServiceIRI, refType)
	}

	logger.Debugf("[%s] %s (if found) was successfully deleted from %s's collection of %s",
		h.ServiceIRI, actorIRI, h.ServiceIRI, refType)

	return nil
}

func (h *Inbox) getAnnounceToList(create *vocab.ActivityType) ([]*url.URL, error) {
	it, err := h.store.QueryReferences(store.Follower, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
	if err != nil {
		return nil, err
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	followers, err := storeutil.ReadReferences(it, -1)
	if err != nil {
		return nil, err
	}

	var announceTo []*url.URL

	for _, follower := range followers {
		if follower.String() == create.Actor().String() {
			logger.Debugf("[%s] Not announcing to follower [%s] since it is the originator of the 'Create'",
				h.ServiceIRI, follower)

			continue
		}

		announceTo = append(announceTo, follower)
	}

	return announceTo, nil
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

type noOpAnchorCredentialPublisher struct{}

func (p *noOpAnchorCredentialPublisher) HandleAnchorCredential(*url.URL, string, []byte) error {
	return nil
}

type acceptAllActorsAuth struct{}

func (a *acceptAllActorsAuth) AuthorizeActor(*vocab.ActorType) (bool, error) {
	return true, nil
}

type noOpProofHandler struct{}

func (p *noOpProofHandler) HandleProof(anchorCredID string, startTime, endTime time.Time, proof []byte) error {
	return nil
}
