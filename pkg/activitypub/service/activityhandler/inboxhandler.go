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

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var errDuplicateAnchorCredential = errors.New("anchor credential already handled")

// Inbox handles activities posted to the inbox.
type Inbox struct {
	*handler
	*service.Handlers

	outbox       service.Outbox
	followersIRI *url.URL
}

// NewInbox returns a new ActivityPub inbox activity handler.
func NewInbox(cfg *Config, s store.Store, outbox service.Outbox,
	activityPubClient activityPubClient, opts ...service.HandlerOpt) *Inbox {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	followersIRI, err := url.Parse(cfg.ServiceIRI.String() + resthandler.FollowersPath)
	if err != nil {
		// This would only happen at startup and it would be a result of bad configuration.
		panic(fmt.Errorf("followers IRI: %w", err))
	}

	h := &Inbox{
		outbox:       outbox,
		Handlers:     options,
		followersIRI: followersIRI,
	}

	h.handler = newHandler(cfg, s, activityPubClient,
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
func (h *Inbox) HandleActivity(activity *vocab.ActivityType) error {
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
			logger.Warnf("[%s] Unable to announce 'Create' activity [%s] to our followers: %s",
				h.ServiceIRI, create.ID(), err)
		}

	case t.Is(vocab.TypeAnchorCredentialRef):
		ref := obj.AnchorCredentialReference()

		if err := h.handleAnchorCredential(ref.Target(), ref.Object().Object()); err != nil {
			return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
		}

		if err := h.announceAnchorCredentialRef(create); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' activity [%s] to our followers: %s",
				h.ServiceIRI, create.ID(), err)
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

	actor, err := h.client.GetActor(actorIRI)
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
		return orberrors.NewTransient(fmt.Errorf("unable to store reference: %w", err))
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

	// Make sure that the original activity was posted to our outbox, otherwise it may be an attempt
	// to forcefully add an unsolicited follower/witness.
	origActivity, err := h.ensureActivityInOutbox(activity)
	if err != nil {
		return fmt.Errorf("ensure target activity of 'Accept' is in outbox %s: %w", activity.ID(), err)
	}

	switch {
	case activity.Type().Is(vocab.TypeFollow):
		if err := h.handleAccept(accept, store.Following); err != nil {
			return fmt.Errorf("handle accept 'Follow' activity %s: %w", accept.ID(), err)
		}

	case activity.Type().Is(vocab.TypeInviteWitness):
		if err := h.handleAccept(accept, store.Witness); err != nil {
			return fmt.Errorf("handle accept 'InviteWitness' activity %s: %w", accept.ID(), err)
		}

	case activity.Type().Is(vocab.TypeOffer):
		if err := h.handleAcceptOfferActivity(accept, origActivity); err != nil {
			return fmt.Errorf("handle accept 'Offer' activity %s: %w", accept.ID(), err)
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
		return orberrors.NewTransient(fmt.Errorf("handle accept '%s' activity %s: %w", refType, accept.ID(), err))
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

	if !activity.Type().IsAny(vocab.TypeFollow, vocab.TypeInviteWitness, vocab.TypeOffer) {
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
		return orberrors.NewTransient(fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err))
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
		return orberrors.NewTransient(fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err))
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
		return false, orberrors.NewTransient(fmt.Errorf("query references: %w", err))
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

		return false, orberrors.NewTransient(fmt.Errorf("get next reference: %w", err))
	}

	return true, nil
}

func (h *Inbox) handleAnnounceActivity(announce *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Announce' activity: %s", h.ServiceName, announce.ID())

	obj := announce.Object()

	t := obj.Type()

	switch {
	case t.Is(vocab.TypeCollection):
		if err := h.handleAnnounceCollection(announce, obj.Collection().Items()); err != nil {
			return fmt.Errorf("error handling 'Announce' activity [%s]: %w", announce.ID(), err)
		}

	case t.Is(vocab.TypeOrderedCollection):
		if err := h.handleAnnounceCollection(announce, obj.OrderedCollection().Items()); err != nil {
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

	// Create a new offer activity with only the bare essentials to return in the 'Accept'.
	oa := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithIRI(offer.Object().Object().ID().URL())),
		vocab.WithID(offer.ID().URL()),
		vocab.WithActor(offer.Actor()),
		vocab.WithTo(offer.To()...),
		vocab.WithTarget(offer.Target()),
	)

	accept := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(oa)),
		vocab.WithTo(oa.Actor(), vocab.PublicIRI),
		vocab.WithResult(vocab.NewObjectProperty(
			vocab.WithObject(vocab.NewObject(
				vocab.WithType(vocab.TypeAnchorReceipt),
				vocab.WithInReplyTo(anchorCred.ID().URL()),
				vocab.WithStartTime(&startTime),
				vocab.WithEndTime(&endTime),
				vocab.WithAttachment(result),
			),
			),
		)),
	)

	_, err = h.outbox.Post(accept)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to reply with 'Like' to %s for offer [%s]: %w",
			offer.Actor(), offer.ID(), err))
	}

	h.notify(offer)

	return nil
}

func (h *Inbox) handleAcceptOfferActivity(accept, offer *vocab.ActivityType) error {
	logger.Infof("[%s] Handling 'Accept' offer activity: %s", h.ServiceName, accept.ID())

	err := h.validateAcceptOfferActivity(accept)
	if err != nil {
		return fmt.Errorf("invalid 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	result := accept.Result().Object()

	anchorCredID := result.InReplyTo()

	if offer.Object().Object().ID().String() != anchorCredID.String() {
		return errors.New("the anchor credential in the original 'Offer' does not match the IRI in the 'inReplyTo' field")
	}

	attachmentBytes, err := json.Marshal(result.Attachment()[0])
	if err != nil {
		return fmt.Errorf("marshal error of attachment in 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	err = h.ProofHandler.HandleProof(accept.Actor(), anchorCredID.String(), *result.EndTime(), attachmentBytes)
	if err != nil {
		return fmt.Errorf("proof handler returned error for 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	h.notify(accept)

	return nil
}

func (h *Inbox) handleAnchorCredential(target *vocab.ObjectProperty, obj *vocab.ObjectType) error {
	if !target.Type().Is(vocab.TypeContentAddressedStorage) {
		return fmt.Errorf("unsupported target type %s", target.Type().Types())
	}

	targetIRI := target.Object().ID().URL()

	ok, err := h.hasReference(targetIRI, h.ServiceIRI, store.AnchorCredential)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("has anchor credential [%s]: %w", targetIRI, err))
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
		return orberrors.NewTransient(fmt.Errorf("store anchor credential reference: %w", err))
	}

	return nil
}

func (h *Inbox) handleAnnounceCollection(announce *vocab.ActivityType, items []*vocab.ObjectProperty) error {
	logger.Infof("[%s] Handling announce collection. Items: %+v\n", h.ServiceIRI, items)

	var anchorCredIDs []*url.URL

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

			logger.Infof("[%s] Ignoring duplicate anchor credential [%s]",
				h.ServiceIRI, ref.Target().Object().ID())
		} else {
			anchorCredIDs = append(anchorCredIDs, ref.ID().URL())
		}
	}

	for _, anchorCredID := range anchorCredIDs {
		logger.Debugf("[%s] Adding 'Announce' [%s] to shares of anchor credential [%s]",
			h.ServiceIRI, announce.ID(), anchorCredID)

		err := h.store.AddReference(store.Share, anchorCredID, announce.ID().URL())
		if err != nil {
			// This isn't a fatal error so just log a warning.
			logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of anchor credential %s: %s",
				h.ServiceIRI, announce.ID(), anchorCredID, err)
		}
	}

	return nil
}

func (h *Inbox) announceAnchorCredential(create *vocab.ActivityType) error {
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
		vocab.WithTo(h.followersIRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&published),
	)

	_, err = h.outbox.Post(announce)
	if err != nil {
		return orberrors.NewTransient(err)
	}

	return nil
}

func (h *Inbox) announceAnchorCredentialRef(create *vocab.ActivityType) error {
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
		vocab.WithTo(h.followersIRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&published),
	)

	activityID, err := h.outbox.Post(announce)
	if err != nil {
		return orberrors.NewTransient(err)
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

	if offer.Target().IRI() == nil || offer.Target().IRI().String() != vocab.AnchorWitnessTargetIRI.String() {
		return fmt.Errorf("object target IRI must be set to %s", vocab.AnchorWitnessTargetIRI)
	}

	obj := offer.Object().Object()

	if obj == nil {
		return fmt.Errorf("object is required")
	}

	if !obj.Type().Is(vocab.TypeAnchorCredential, vocab.TypeVerifiableCredential) {
		return fmt.Errorf("unsupported object type in Offer activity %s", obj.Type())
	}

	if obj.ID() == nil {
		return fmt.Errorf("object ID is required")
	}

	return nil
}

func (h *Inbox) validateAcceptOfferActivity(accept *vocab.ActivityType) error {
	a := accept.Object().Activity()

	if a == nil {
		return errors.New("object is required")
	}

	if a.Object().IRI() == nil {
		return errors.New("object IRI is required")
	}

	if !a.Type().Is(vocab.TypeOffer) {
		return errors.New("object is not of type 'Offer'")
	}

	if a.Target().IRI() == nil || a.Target().IRI().String() != vocab.AnchorWitnessTargetIRI.String() {
		return fmt.Errorf("object target IRI must be set to %s", vocab.AnchorWitnessTargetIRI)
	}

	result := accept.Result().Object()

	if result == nil {
		return errors.New("result is required")
	}

	if result.StartTime() == nil {
		return errors.New("result startTime is required")
	}

	if result.EndTime() == nil {
		return errors.New("result endTime is required")
	}

	if len(result.Attachment()) != 1 {
		return errors.New("expecting exactly one attachment")
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
		return orberrors.NewTransient(fmt.Errorf("unable to delete %s from %s's collection of %s",
			actorIRI, h.ServiceIRI, refType))
	}

	logger.Debugf("[%s] %s (if found) was successfully deleted from %s's collection of %s",
		h.ServiceIRI, actorIRI, h.ServiceIRI, refType)

	return nil
}

func (h *Inbox) ensureActivityInOutbox(activity *vocab.ActivityType) (*vocab.ActivityType, error) {
	obActivity, err := h.getActivityFromOutbox(activity.ID().URL())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("get activity from outbox: %w", err)
		}

		return nil, orberrors.NewTransient(fmt.Errorf("get activity from outbox: %w", err))
	}

	// Ensure the activity in the outbox is the same as the given activity.
	err = ensureSameActivity(obActivity, activity)
	if err != nil {
		return nil, fmt.Errorf("activity not the same as the one in outbox: %w", err)
	}

	return obActivity, nil
}

func (h *Inbox) getActivityFromOutbox(activityIRI *url.URL) (*vocab.ActivityType, error) {
	it, err := h.store.QueryActivities(store.NewCriteria(
		store.WithReferenceType(store.Outbox),
		store.WithObjectIRI(h.ServiceIRI),
		store.WithReferenceIRI(activityIRI)),
	)
	if err != nil {
		return nil, fmt.Errorf("query outbox: %w", err)
	}

	activities, err := storeutil.ReadActivities(it, -1)
	if err != nil {
		return nil, fmt.Errorf("read activities: %w", err)
	}

	if len(activities) == 0 {
		return nil, store.ErrNotFound
	}

	return activities[0], nil
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

func ensureSameActivity(a1, a2 *vocab.ActivityType) error {
	if a1.Actor().String() != a2.Actor().String() {
		return fmt.Errorf("actors do not match: [%s] and [%s]", a1.Actor(), a2.Actor())
	}

	if !a1.Type().Is(a2.Type().Types()...) || !a2.Type().Is(a1.Type().Types()...) {
		return fmt.Errorf("types do not match: %s and %s", a1.Type(), a2.Type())
	}

	return nil
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

func (p *noOpProofHandler) HandleProof(witness *url.URL, anchorCredID string, endTime time.Time, proof []byte) error { //nolint:lll
	return nil
}
