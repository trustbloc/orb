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
	"github.com/trustbloc/orb/pkg/anchor/util"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
)

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
			return h.undoAddReference(activity, store.Follower, func() *url.URL {
				return activity.Object().IRI()
			})
		},
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Witnessing, func() *url.URL {
				return activity.Target().IRI()
			})
		},
		h.inboxUndoLike,
	)

	return h
}

// HandleActivity handles the ActivityPub activity in the inbox.
//nolint:cyclop
func (h *Inbox) HandleActivity(activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.HandleCreateActivity(activity, true)
	case typeProp.Is(vocab.TypeFollow):
		return h.handleFollowActivity(activity)
	case typeProp.Is(vocab.TypeInvite):
		return h.handleInviteActivity(activity)
	case typeProp.Is(vocab.TypeAccept):
		return h.handleAcceptActivity(activity)
	case typeProp.Is(vocab.TypeReject):
		return h.handleRejectActivity(activity)
	case typeProp.Is(vocab.TypeAnnounce):
		return h.HandleAnnounceActivity(activity)
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

// HandleCreateActivity handles a 'Create' ActivityPub activity.
func (h *Inbox) HandleCreateActivity(create *vocab.ActivityType, announce bool) error {
	logger.Debugf("[%s] Handling 'Create' activity: %s", h.ServiceName, create.ID())

	if !create.Object().Type().Is(vocab.TypeAnchorEvent) {
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", create.Object().Type(), create.ID())
	}

	anchorEvent := create.Object().AnchorEvent()

	err := anchorEvent.Validate()
	if err != nil {
		return fmt.Errorf("invalid anchor event: %w", err)
	}

	if anchorEvent.Index() != nil {
		err = h.handleEmbeddedAnchorEvent(create, anchorEvent, announce)
	} else {
		err = h.handleAnchorEventRef(create, anchorEvent.URL()[0], announce)
	}

	if err != nil {
		return err
	}

	h.notify(create)

	return nil
}

func (h *Inbox) handleEmbeddedAnchorEvent(create *vocab.ActivityType,
	anchorEvent *vocab.AnchorEventType, announce bool) error {
	if len(anchorEvent.URL()) == 0 {
		return errors.New("missing anchor event URL")
	}

	if err := h.handleAnchorEvent(create.Actor(), anchorEvent); err != nil {
		return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
	}

	if announce {
		if err := h.announceAnchorEvent(create); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' activity [%s] to our followers: %s",
				h.ServiceIRI, create.ID(), err)
		}
	}

	return nil
}

func (h *Inbox) handleAnchorEventRef(create *vocab.ActivityType, anchorEventURL *url.URL, announce bool) error {
	if err := h.handleAnchorEventReference(create.Actor(), anchorEventURL); err != nil {
		return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
	}

	if announce {
		if err := h.announceAnchorEventRef(create); err != nil {
			logger.Warnf("[%s] Unable to announce 'Create' activity [%s] to our followers: %s",
				h.ServiceIRI, create.ID(), err)
		}
	}

	return nil
}

func (h *Inbox) handleReferenceActivity(activity *vocab.ActivityType, refType store.ReferenceType,
	auth service.ActorAuth, getTargetIRI func() *url.URL) error {
	logger.Debugf("[%s] Handling '%s' activity: %s", h.ServiceName, activity.Type(), activity.ID())

	err := h.validateActivity(activity, getTargetIRI)
	if err != nil {
		return fmt.Errorf("validate '%s' activity [%s]: %w", activity.Type(), activity.ID(), err)
	}

	actorIRI := activity.Actor()

	hasRef, err := h.hasReference(h.ServiceIRI, actorIRI, refType)
	if err != nil {
		return err
	}

	if hasRef {
		logger.Debugf("[%s] Actor %s already has %s in its %s collection. Replying with 'Accept' activity.",
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
		logger.Debugf("[%s] Request for %s to activity %s has been accepted", h.ServiceName, h.ServiceIRI, actor.ID())

		return h.acceptActor(activity, actor, refType)
	}

	logger.Debugf("[%s] Request for %s to activity %s has been rejected. Replying with 'Reject' activity",
		h.ServiceName, actorIRI, h.ServiceIRI)

	return h.postReject(activity, actorIRI)
}

func (h *Inbox) handleFollowActivity(follow *vocab.ActivityType) error {
	return h.handleReferenceActivity(follow, store.Follower, h.FollowerAuth,
		func() *url.URL {
			return follow.Object().IRI()
		},
	)
}

func (h *Inbox) handleInviteActivity(invite *vocab.ActivityType) error {
	object := invite.Object().IRI()

	if object == nil {
		return fmt.Errorf("no object specified in 'Invite' activity")
	}

	if object.String() == vocab.AnchorWitnessTargetIRI.String() {
		return h.handleReferenceActivity(invite, store.Witnessing, h.WitnessInvitationAuth,
			func() *url.URL {
				return invite.Target().IRI()
			},
		)
	}

	return fmt.Errorf("unsupported object type for 'Invite' activity: %s", object)
}

func (h *Inbox) validateActivity(activity *vocab.ActivityType, getTargetIRI func() *url.URL) error {
	if activity.Actor() == nil {
		return fmt.Errorf("no actor specified")
	}

	iri := getTargetIRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified")
	}

	// Make sure that the IRI is targeting this service. If not then ignore the message
	if iri.String() != h.ServiceIRI.String() {
		return fmt.Errorf("this service is not the target object for the '%s'", activity.Type())
	}

	return nil
}

func (h *Inbox) acceptActor(activity *vocab.ActivityType, actor *vocab.ActorType, refType store.ReferenceType) error {
	if err := h.store.AddReference(refType, h.ServiceIRI, actor.ID().URL(),
		store.WithActivityType(activity.Type().Types()[0])); err != nil {
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

	case activity.Type().Is(vocab.TypeInvite):
		if err := h.handleAcceptInviteActivity(accept); err != nil {
			return fmt.Errorf("handle accept 'Invite' activity %s: %w", accept.ID(), err)
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

	err = h.store.AddReference(refType, h.ServiceIRI, accept.Actor(), store.WithActivityType(accept.Type().Types()[0]))
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

	if !activity.Type().IsAny(vocab.TypeFollow, vocab.TypeInvite, vocab.TypeOffer) {
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

func (h *Inbox) handleAcceptInviteActivity(accept *vocab.ActivityType) error {
	objectIRI := accept.Object().Activity().Object().IRI()

	if objectIRI == nil {
		return fmt.Errorf("no object IRI specified in 'Invite' activity")
	}

	if objectIRI.String() == vocab.AnchorWitnessTargetIRI.String() {
		err := h.handleAccept(accept, store.Witness)
		if err != nil {
			return fmt.Errorf("handle accept 'Invite' witness activity %s: %w", accept.ID(), err)
		}

		return nil
	}

	return fmt.Errorf("unsupported object for accept 'Invite' activity: %s", objectIRI)
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

// HandleAnnounceActivity handles an 'Announce' ActivityPub activity.
func (h *Inbox) HandleAnnounceActivity(announce *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Announce' activity: %s", h.ServiceName, announce.ID())

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
	logger.Debugf("[%s] Handling 'Offer' activity: %s", h.ServiceName, offer.ID())

	err := h.validateOfferActivity(offer)
	if err != nil {
		return fmt.Errorf("invalid 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	if time.Now().After(*offer.EndTime()) {
		return fmt.Errorf("offer [%s] has expired", offer.ID())
	}

	anchorEvent := offer.Object().AnchorEvent()

	witnessDoc, err := util.GetWitnessDoc(anchorEvent)
	if err != nil {
		return fmt.Errorf("get witness document for 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	result, err := h.witnessAnchorCredential(witnessDoc)
	if err != nil {
		return fmt.Errorf("error creating result for 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	startTime := time.Now()
	endTime := startTime.Add(h.MaxWitnessDelay)

	// Create a new offer activity with only the bare essentials to return in the 'Accept'.
	oa := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithIRI(anchorEvent.Index())),
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
				vocab.WithInReplyTo(anchorEvent.Index()),
				vocab.WithStartTime(&startTime),
				vocab.WithEndTime(&endTime),
				vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result))),
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
	logger.Debugf("[%s] Handling 'Accept' offer activity: %s", h.ServiceName, accept.ID())

	err := h.validateAcceptOfferActivity(accept)
	if err != nil {
		return fmt.Errorf("invalid 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	result := accept.Result().Object()

	inReplyTo := result.InReplyTo()

	anchorEvent := offer.Object().AnchorEvent()

	if anchorEvent.Index() == nil {
		return errors.New("the anchor event in the original 'Offer' is empty")
	}

	if anchorEvent.Index().String() != inReplyTo.String() {
		return errors.New(
			"the anchors URL of the anchor event in the original 'Offer' does not match the IRI in the 'inReplyTo' field",
		)
	}

	attachmentBytes, err := json.Marshal(result.Attachment()[0])
	if err != nil {
		return fmt.Errorf("marshal error of attachment in 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	err = h.ProofHandler.HandleProof(accept.Actor(), anchorEvent.Index().String(), *result.EndTime(), attachmentBytes)
	if err != nil {
		return fmt.Errorf("proof handler returned error for 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	h.notify(accept)

	return nil
}

func (h *Inbox) handleAnchorEvent(actor *url.URL, anchorEvent *vocab.AnchorEventType) error {
	anchorEventRef := anchorEvent.URL()[0]

	ok, err := h.hasReference(anchorEventRef, h.ServiceIRI, store.AnchorEvent)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("has anchor event reference [%s]: %w",
			anchorEventRef, err))
	}

	if ok {
		return fmt.Errorf("handle anchor event [%s]: %w", anchorEventRef, service.ErrDuplicateAnchorEvent)
	}

	// Create a new anchor event without the URL property since this data is an add-on that's only used by
	// ActivityPub in the 'Create" and "Announce" activities.
	ae := vocab.NewAnchorEvent(
		vocab.WithAttributedTo(anchorEvent.AttributedTo().URL()),
		vocab.WithAnchors(anchorEvent.Index()),
		vocab.WithPublishedTime(anchorEvent.Published()),
		vocab.WithParent(anchorEvent.Parent()...),
		vocab.WithAttachment(anchorEvent.Attachment()...),
	)

	err = h.AnchorEventHandler.HandleAnchorEvent(actor, anchorEventRef, ae)
	if err != nil {
		return fmt.Errorf("handle anchor event: %w", err)
	}

	logger.Debugf("[%s] Storing anchor event reference [%s]", h.ServiceName, anchorEventRef)

	err = h.store.AddReference(store.AnchorEvent, anchorEventRef, h.ServiceIRI)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor event reference: %w", err))
	}

	return nil
}

func (h *Inbox) handleAnchorEventReference(actor, anchorEventRef *url.URL) error {
	ok, err := h.hasReference(anchorEventRef, h.ServiceIRI, store.AnchorEvent)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("has anchor event reference [%s]: %w",
			anchorEventRef, err))
	}

	if ok {
		return fmt.Errorf("handle anchor event [%s]: %w", anchorEventRef, service.ErrDuplicateAnchorEvent)
	}

	err = h.AnchorEventHandler.HandleAnchorEvent(actor, anchorEventRef, nil)
	if err != nil {
		return fmt.Errorf("handle anchor event: %w", err)
	}

	logger.Debugf("[%s] Storing anchor event reference [%s]", h.ServiceName, anchorEventRef)

	err = h.store.AddReference(store.AnchorEvent, anchorEventRef, h.ServiceIRI)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor event reference: %w", err))
	}

	return nil
}

func (h *Inbox) handleAnnounceCollection(announce *vocab.ActivityType, items []*vocab.ObjectProperty) error { //nolint:gocyclo,cyclop,lll
	logger.Debugf("[%s] Handling announce collection. Items: %+v\n", h.ServiceIRI, items)

	var anchorEventIDs []*url.URL

	for _, item := range items {
		if !item.Type().Is(vocab.TypeAnchorEvent) {
			return fmt.Errorf("expecting 'Info' type")
		}

		anchorEvent := item.AnchorEvent()

		if err := anchorEvent.Validate(); err != nil {
			// Continue processing other anchor events on invalid anchor event.
			logger.Infof("[%s] Ignoring invalid anchor event %s", h.ServiceIRI, anchorEvent.URL())

			continue
		}

		if anchorEvent.Index() != nil { //nolint:nestif
			if err := h.handleAnchorEvent(announce.Actor(), anchorEvent); err != nil {
				// Continue processing other anchor events on duplicate error.
				if !errors.Is(err, service.ErrDuplicateAnchorEvent) {
					return err
				}

				logger.Debugf("[%s] Ignoring duplicate anchor event %s", h.ServiceIRI, anchorEvent.URL())
			} else {
				anchorEventIDs = append(anchorEventIDs, anchorEvent.URL()[0])
			}
		} else {
			if err := h.handleAnchorEventReference(announce.Actor(), anchorEvent.URL()[0]); err != nil {
				// Continue processing other anchor events on duplicate error.
				if !errors.Is(err, service.ErrDuplicateAnchorEvent) {
					return err
				}

				logger.Debugf("[%s] Ignoring duplicate anchor event %s", h.ServiceIRI, anchorEvent.URL())
			} else {
				anchorEventIDs = append(anchorEventIDs, anchorEvent.URL()[0])
			}
		}
	}

	for _, anchorEventID := range anchorEventIDs {
		logger.Debugf("[%s] Adding 'Announce' [%s] to shares of anchor event [%s]",
			h.ServiceIRI, announce.ID(), anchorEventID)

		err := h.store.AddReference(store.Share, anchorEventID, announce.ID().URL(),
			store.WithActivityType(announce.Type().Types()[0]))
		if err != nil {
			// This isn't a fatal error so just log a warning.
			logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of anchor event %s: %s",
				h.ServiceIRI, announce.ID(), anchorEventID, err)
		}
	}

	return nil
}

func (h *Inbox) handleLikeActivity(like *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Like' activity: %s", h.ServiceName, like.ID())

	if err := h.validateLikeActivity(like); err != nil {
		return fmt.Errorf("invalid 'Like' activity [%s]: %w", like.ID(), err)
	}

	// TODO: Will there always be only one URL?
	refURL := like.Object().AnchorEvent().URL()[0]

	var additionalRefs []*url.URL

	if like.Result() != nil {
		additionalRefs = like.Result().AnchorEvent().URL()
	}

	if err := h.AnchorEventAckHandler.AnchorEventAcknowledged(like.Actor(), refURL, additionalRefs); err != nil {
		return fmt.Errorf("error creating result for 'Like' activity [%s]: %w", like.ID(), err)
	}

	logger.Debugf("[%s] Storing activity in the 'Likes' collection: %s", h.ServiceName, refURL)

	if err := h.store.AddReference(store.Like, refURL, like.ID().URL(),
		store.WithActivityType(like.Type().Types()[0])); err != nil {
		return orberrors.NewTransient(fmt.Errorf("add activity to 'Likes' collection: %w", err))
	}

	h.notify(like)

	return nil
}

func (h *Inbox) announceAnchorEvent(create *vocab.ActivityType) error {
	anchorEvent := create.Object().AnchorEvent()

	published := time.Now()

	announce := vocab.NewAnnounceActivity(
		vocab.NewObjectProperty(
			vocab.WithCollection(
				vocab.NewCollection(
					[]*vocab.ObjectProperty{
						vocab.NewObjectProperty(
							vocab.WithAnchorEvent(anchorEvent),
						),
					},
				),
			),
		),
		vocab.WithTo(h.followersIRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&published),
	)

	if _, err := h.outbox.Post(announce); err != nil {
		return orberrors.NewTransient(err)
	}

	return nil
}

func (h *Inbox) announceAnchorEventRef(create *vocab.ActivityType) error {
	if len(create.Object().AnchorEvent().URL()) == 0 {
		return fmt.Errorf("missing URL in anchor reference for 'Create' activity [%s]", create.ID())
	}

	anchorEventURL := create.Object().AnchorEvent().URL()[0]

	published := time.Now()

	announce := vocab.NewAnnounceActivity(
		vocab.NewObjectProperty(
			vocab.WithCollection(
				vocab.NewCollection(
					[]*vocab.ObjectProperty{
						vocab.NewObjectProperty(
							vocab.WithURL(anchorEventURL),
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

	logger.Debugf("[%s] Adding 'Announce' %s to shares of %s", h.ServiceIRI, announce.ID(), anchorEventURL)

	err = h.store.AddReference(store.Share, anchorEventURL, activityID,
		store.WithActivityType(create.Type().Types()[0]))
	if err != nil {
		logger.Warnf("[%s] Error adding 'Announce' activity %s to 'shares' of %s",
			h.ServiceIRI, announce.ID(), anchorEventURL)
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

	anchorEvent := offer.Object().AnchorEvent()
	if anchorEvent == nil {
		return fmt.Errorf("anchor event is required")
	}

	err := anchorEvent.Validate()
	if err != nil {
		return fmt.Errorf("invalid anchor event: %w", err)
	}

	if anchorEvent.Index() == nil {
		return fmt.Errorf("anchors URL is required in anchor event: %w", err)
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

func (h *Inbox) validateLikeActivity(like *vocab.ActivityType) error {
	if like.Actor() == nil {
		return fmt.Errorf("actor is required")
	}

	ref := like.Object().AnchorEvent()

	if len(ref.URL()) == 0 {
		return fmt.Errorf("anchor reference URL is required")
	}

	return nil
}

func (h *Inbox) witnessAnchorCredential(vc vocab.Document) (*vocab.ObjectType, error) {
	bytes, err := json.Marshal(vc)
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

func (h *Inbox) undoAddReference(activity *vocab.ActivityType, refType store.ReferenceType,
	getTargetIRI func() *url.URL) error {
	iri := getTargetIRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in the '%s' activity", activity.Type())
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

func (h *Inbox) inboxUndoLike(like *vocab.ActivityType) error {
	ref := like.Object().AnchorEvent()

	if ref == nil || len(ref.URL()) == 0 {
		return fmt.Errorf("invalid anchor reference in the 'Like' activity")
	}

	u := ref.URL()[0]

	err := h.store.DeleteReference(store.Like, u, like.ID().URL())
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to delete %s from %s's collection of 'Likes'",
			like.ID(), u))
	}

	logger.Debugf("[%s] %s (if found) was successfully deleted from %s's collection of 'Likes'",
		h.ServiceIRI, like.ID(), u)

	// TODO: Will there always be only one URL?
	refURL := like.Object().AnchorEvent().URL()[0]

	var additionalRefs []*url.URL

	if like.Result() != nil {
		additionalRefs = like.Result().AnchorEvent().URL()
	}

	if err := h.AnchorEventAckHandler.UndoAnchorEventAcknowledgement(like.Actor(), refURL, additionalRefs); err != nil {
		return fmt.Errorf("error undoing 'Like' activity [%s]: %w", like.ID(), err)
	}

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

func (p *noOpAnchorCredentialPublisher) HandleAnchorEvent(_, _ *url.URL, _ *vocab.AnchorEventType) error {
	return nil
}

// AcceptAllActorsAuth is an authorization handler that accepts any actor.
type AcceptAllActorsAuth struct{}

// AuthorizeActor authorizes the actor. This implementation always returns true.
func (a *AcceptAllActorsAuth) AuthorizeActor(*vocab.ActorType) (bool, error) {
	return true, nil
}

type noOpProofHandler struct{}

func (p *noOpProofHandler) HandleProof(witness *url.URL, anchorCredID string,
	endTime time.Time, proof []byte) error {
	return nil
}

type noOpAnchorEventAcknowledgementHandler struct{}

func (p *noOpAnchorEventAcknowledgementHandler) AnchorEventAcknowledged(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL) error {
	logger.Debugf("Anchor event was acknowledged by [%s] for anchor %s. Additional anchors: %s",
		actor, hashlink.ToString(anchorRef), hashlink.ToString(additionalAnchorRefs...))

	return nil
}

func (p *noOpAnchorEventAcknowledgementHandler) UndoAnchorEventAcknowledgement(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL) error {
	logger.Debugf("Anchor event was undone by [%s] for anchor %s. Additional anchors: %s",
		actor, hashlink.ToString(anchorRef), hashlink.ToString(additionalAnchorRefs...))

	return nil
}
