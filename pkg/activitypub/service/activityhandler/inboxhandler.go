/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	store2 "github.com/trustbloc/orb/pkg/store"
)

// Inbox handles activities posted to the inbox.
type Inbox struct {
	*handler
	*service.Handlers

	outbox       service.Outbox
	followersIRI *url.URL
	tracer       trace.Tracer
}

// NewInbox returns a new ActivityPub inbox activity handler.
func NewInbox(cfg *Config, s store.Store, outbox service.Outbox,
	activityPubClient activityPubClient, opts ...service.HandlerOpt,
) *Inbox {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	followersIRI, err := url.Parse(cfg.ServiceEndpointURL.String() + resthandler.FollowersPath)
	if err != nil {
		// This would only happen at startup and it would be a result of bad configuration.
		panic(fmt.Errorf("followers IRI: %w", err))
	}

	h := &Inbox{
		outbox:       outbox,
		Handlers:     options,
		followersIRI: followersIRI,
		tracer:       tracing.Tracer(tracing.SubsystemActivityPub),
	}

	h.handler = newHandler(cfg, s, activityPubClient,
		func(activity *vocab.ActivityType) error {
			return h.undoFollowReference(activity, func() *url.URL {
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
//
//nolint:cyclop
func (h *Inbox) HandleActivity(ctx context.Context, source *url.URL, activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	spanCtx, span := h.tracer.Start(ctx, fmt.Sprintf("inbox handle %s activity", typeProp),
		trace.WithAttributes(
			tracing.ActivityIDAttribute(activity.ID().String()),
			tracing.ActivityTypeAttribute(typeProp.String()),
		))
	defer span.End()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.HandleCreateActivity(spanCtx, source, activity, true)
	case typeProp.Is(vocab.TypeFollow):
		return h.handleFollowActivity(spanCtx, activity)
	case typeProp.Is(vocab.TypeInvite):
		return h.handleInviteActivity(spanCtx, activity)
	case typeProp.Is(vocab.TypeAccept):
		return h.handleAcceptActivity(spanCtx, activity)
	case typeProp.Is(vocab.TypeReject):
		return h.handleRejectActivity(activity)
	case typeProp.Is(vocab.TypeAnnounce):
		_, err := h.HandleAnnounceActivity(spanCtx, source, activity)

		return err
	case typeProp.Is(vocab.TypeOffer):
		return h.handleOfferActivity(spanCtx, activity)
	case typeProp.Is(vocab.TypeLike):
		return h.handleLikeActivity(activity)
	case typeProp.Is(vocab.TypeUndo):
		return h.handleUndoActivity(spanCtx, activity)
	default:
		return fmt.Errorf("unsupported activity type: %s", typeProp.Types())
	}
}

// HandleCreateActivity handles a 'Create' ActivityPub activity.
func (h *Inbox) HandleCreateActivity(ctx context.Context, source *url.URL, create *vocab.ActivityType, announce bool) error {
	h.logger.Debugc(ctx, "Handling 'Create' activity", logfields.WithActivityID(create.ID()))

	if !create.Object().Type().Is(vocab.TypeAnchorEvent) {
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", create.Object().Type(), create.ID())
	}

	anchorEvent := create.Object().AnchorEvent()

	err := anchorEvent.Validate()
	if err != nil {
		return fmt.Errorf("invalid anchor event: %w", err)
	}

	if anchorEvent.Object() != nil {
		err = h.handleEmbeddedAnchorEvent(ctx, source, create, anchorEvent, announce)
	} else {
		err = h.handleAnchorEventRef(ctx, source, create, anchorEvent.URL()[0], announce)
	}

	if err != nil {
		return err
	}

	h.notify(create)

	return nil
}

func (h *Inbox) handleEmbeddedAnchorEvent(ctx context.Context, source *url.URL, create *vocab.ActivityType,
	anchorEvent *vocab.AnchorEventType, announce bool,
) error {
	if len(anchorEvent.URL()) == 0 {
		return errors.New("missing anchor URL")
	}

	if err := h.handleAnchorEvent(ctx, create.Actor(), source, anchorEvent); err != nil {
		return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
	}

	if announce {
		if err := h.announceAnchorEvent(ctx, create); err != nil {
			h.logger.Warn("Unable to announce 'Create' activity to our followers: %s",
				logfields.WithActivityID(create.ID()), log.WithError(err))
		}
	}

	return nil
}

func (h *Inbox) handleAnchorEventRef(ctx context.Context, source *url.URL, create *vocab.ActivityType,
	anchorEventURL *url.URL, announce bool,
) error {
	if err := h.handleAnchorEventReference(ctx, create.Actor(), anchorEventURL, source); err != nil {
		return fmt.Errorf("error handling 'Create' activity [%s]: %w", create.ID(), err)
	}

	if announce {
		if err := h.announceAnchorEventRef(ctx, create); err != nil {
			h.logger.Warn("Unable to announce 'Create' activity to our followers",
				logfields.WithActivityID(create.ID()), log.WithError(err))
		}
	}

	return nil
}

func (h *Inbox) handleReferenceActivity(ctx context.Context, activity *vocab.ActivityType, refType store.ReferenceType,
	auth service.ActorAuth, getTargetIRI func() *url.URL,
) error {
	h.logger.Debug("Handling activity", logfields.WithActivityType(activity.Type().String()), logfields.WithActivityID(activity.ID()))

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
		h.logger.Debug("Reference already exists. Replying with 'Accept' activity.",
			logfields.WithActorIRI(actorIRI), logfields.WithServiceIRI(h.ServiceIRI),
			logfields.WithReferenceType(string(refType)), logfields.WithActivityID(activity.ID()))

		return h.postAccept(ctx, activity, actorIRI)
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
		h.logger.Debug("Request has been accepted. Adding reference to actor and replying with 'Accept' activity.",
			logfields.WithActorIRI(actorIRI), logfields.WithServiceIRI(h.ServiceIRI),
			logfields.WithReferenceType(string(refType)), logfields.WithActivityID(activity.ID()))

		return h.acceptActor(ctx, activity, actor, refType)
	}

	h.logger.Debug("Request has been rejected. Replying with 'Reject' activity.",
		logfields.WithActorIRI(actorIRI), logfields.WithServiceIRI(h.ServiceIRI),
		logfields.WithReferenceType(string(refType)), logfields.WithActivityID(activity.ID()))

	return h.postReject(ctx, activity, actorIRI)
}

func (h *Inbox) handleFollowActivity(ctx context.Context, follow *vocab.ActivityType) error {
	return h.handleReferenceActivity(ctx, follow, store.Follower, h.FollowerAuth,
		func() *url.URL {
			return follow.Object().IRI()
		},
	)
}

func (h *Inbox) handleInviteActivity(ctx context.Context, invite *vocab.ActivityType) error {
	object := invite.Object().IRI()

	if object == nil {
		return fmt.Errorf("no object specified in 'Invite' activity")
	}

	if object.String() == vocab.AnchorWitnessTargetIRI.String() {
		return h.handleReferenceActivity(ctx, invite, store.Witnessing, h.WitnessInvitationAuth,
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

func (h *Inbox) acceptActor(ctx context.Context, activity *vocab.ActivityType, actor *vocab.ActorType, refType store.ReferenceType) error {
	if err := h.store.AddReference(refType, h.ServiceIRI, actor.ID().URL()); err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to store reference: %w", err))
	}

	return h.postAccept(ctx, activity, actor.ID().URL())
}

func (h *Inbox) handleAcceptActivity(ctx context.Context, accept *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Accept' activity", logfields.WithActivityID(accept.ID()))

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
		if err := h.handleAcceptFollow(accept); err != nil {
			return fmt.Errorf("handle accept 'Follow' activity %s: %w", accept.ID(), err)
		}

	case activity.Type().Is(vocab.TypeInvite):
		if err := h.handleAcceptInviteActivity(accept); err != nil {
			return fmt.Errorf("handle accept 'Invite' activity %s: %w", accept.ID(), err)
		}

	case activity.Type().Is(vocab.TypeOffer):
		if err := h.handleAcceptOfferActivity(ctx, accept, origActivity); err != nil {
			return fmt.Errorf("handle accept 'Offer' activity %s: %w", accept.ID(), err)
		}

	default:
		return fmt.Errorf("unsupported activity type [%s] in the 'object' field of the 'Accept' activity",
			activity.Type())
	}

	h.notify(accept)

	return nil
}

func (h *Inbox) handleAcceptFollow(accept *vocab.ActivityType) error {
	err := h.AcceptFollowHandler.Accept(accept.Actor())
	if err != nil {
		return fmt.Errorf("accept follow for actor %s: %w", accept.Actor(), err)
	}

	return h.handleAccept(accept, store.Following)
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
	h.logger.Debug("Handling 'Reject' activity", logfields.WithActivityID(reject.ID()))

	if err := h.validateAcceptRejectActivity(reject); err != nil {
		return err
	}

	h.notify(reject)

	return nil
}

func (h *Inbox) validateAcceptRejectActivity(a *vocab.ActivityType) error {
	h.logger.Debug("Handling accept/reject activity", logfields.WithActivityType(a.Type().String()), logfields.WithActivityID(a.ID()))

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

func (h *Inbox) postAccept(ctx context.Context, activity *vocab.ActivityType, toIRI *url.URL) error {
	acceptActivity := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(activity)),
		vocab.WithTo(toIRI),
	)

	h.notify(activity)

	h.logger.Debug("Publishing 'Accept' activity", logfields.WithTargetIRI(toIRI))

	if _, err := h.outbox.Post(ctx, acceptActivity); err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to reply with 'Accept' to %s: %w", toIRI, err))
	}

	return nil
}

func (h *Inbox) postReject(ctx context.Context, activity *vocab.ActivityType, toIRI *url.URL) error {
	reject := vocab.NewRejectActivity(
		vocab.NewObjectProperty(vocab.WithActivity(activity)),
		vocab.WithTo(toIRI),
	)

	h.logger.Debug("Publishing 'Reject' activity", logfields.WithTargetIRI(toIRI))

	if _, err := h.outbox.Post(ctx, reject); err != nil {
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
			log.CloseIteratorError(h.logger, err)
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
func (h *Inbox) HandleAnnounceActivity(ctx context.Context, source *url.URL, announce *vocab.ActivityType) (numProcessed int, err error) {
	h.logger.Debug("Handling 'Announce' activity", logfields.WithActivityID(announce.ID()))

	obj := announce.Object()

	t := obj.Type()

	switch {
	case t.Is(vocab.TypeCollection):
		numProcessed, err = h.handleAnnounceCollection(ctx, source, announce, obj.Collection().Items())
		if err != nil {
			return numProcessed, fmt.Errorf("error handling 'Announce' activity [%s]: %w", announce.ID(), err)
		}

	case t.Is(vocab.TypeOrderedCollection):
		numProcessed, err = h.handleAnnounceCollection(ctx, source, announce, obj.OrderedCollection().Items())
		if err != nil {
			return numProcessed, fmt.Errorf("error handling 'Announce' activity [%s]: %w", announce.ID(), err)
		}

	default:
		return numProcessed, fmt.Errorf("unsupported object type for 'Announce' %s", t)
	}

	h.notify(announce)

	return numProcessed, nil
}

func (h *Inbox) handleOfferActivity(ctx context.Context, offer *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Offer' activity", logfields.WithActivityID(offer.ID()))

	anchorLink, err := h.validateAndUnmarshalOfferActivity(offer)
	if err != nil {
		return fmt.Errorf("validate 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	vcBytes, err := anchorLink.Replies().Content()
	if err != nil {
		return fmt.Errorf("get content from 'replies' of anchor Linkset: %w", err)
	}

	result, err := h.witnessAnchorCredential(vcBytes)
	if err != nil {
		return fmt.Errorf("error creating result for 'Offer' activity [%s]: %w", offer.ID(), err)
	}

	startTime := time.Now()
	endTime := startTime.Add(h.MaxWitnessDelay)

	// Create a new offer activity with only the bare essentials to return in the 'Accept'.
	oa := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithIRI(anchorLink.Anchor())),
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
				vocab.WithContext(vocab.ContextActivityAnchors),
				vocab.WithType(vocab.TypeAnchorReceipt),
				vocab.WithInReplyTo(anchorLink.Anchor()),
				vocab.WithStartTime(&startTime),
				vocab.WithEndTime(&endTime),
				vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result))),
			),
			),
		)),
	)

	_, err = h.outbox.Post(ctx, accept)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to reply with 'Like' to %s for offer [%s]: %w",
			offer.Actor(), offer.ID(), err))
	}

	h.notify(offer)

	return nil
}

func (h *Inbox) handleAcceptOfferActivity(ctx context.Context, accept, offer *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Accept' offer activity", logfields.WithActivityID(accept.ID()))

	err := h.validateAcceptOfferActivity(accept)
	if err != nil {
		return fmt.Errorf("invalid 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	result := accept.Result().Object()

	inReplyTo := result.InReplyTo()

	anchorLinkset := &linkset.Linkset{}

	err = vocab.UnmarshalFromDoc(offer.Object().Document(), anchorLinkset)
	if err != nil {
		return fmt.Errorf("unmarshal anchor Linkset in original offer activity [%s]: %w", accept.ID(), err)
	}

	if len(anchorLinkset.Linkset) == 0 {
		return fmt.Errorf("anchor Linkset in original offer activity is empty [%s]", accept.ID())
	}

	anchorLink := anchorLinkset.Linkset[0]

	if anchorLink.Anchor() == nil {
		return errors.New("anchor in the anchor Linkset in the original 'Offer' is empty")
	}

	if anchorLink.Anchor().String() != inReplyTo.String() {
		return errors.New(
			"the anchor URI of the anchor Linkset in the original 'Offer' does not match the URI in the 'inReplyTo' field",
		)
	}

	attachmentBytes, err := json.Marshal(result.Attachment()[0])
	if err != nil {
		return fmt.Errorf("marshal error of attachment in 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	err = h.ProofHandler.HandleProof(ctx, accept.Actor(), anchorLink.Anchor().String(), *offer.EndTime(), attachmentBytes)
	if err != nil {
		return fmt.Errorf("proof handler returned error for 'Accept' offer activity [%s]: %w", accept.ID(), err)
	}

	h.notify(accept)

	return nil
}

func (h *Inbox) handleAnchorEvent(ctx context.Context, actor, source *url.URL, anchorEvent *vocab.AnchorEventType) error {
	anchorRef := anchorEvent.URL()[0]

	ok, err := h.hasReference(anchorRef, h.ServiceIRI, store.AnchorLinkset)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("has anchor reference [%s]: %w", anchorRef, err))
	}

	if ok {
		return fmt.Errorf("handle anchor event [%s]: %w", anchorRef, service.ErrDuplicateAnchorEvent)
	}

	err = h.AnchorHandler.HandleAnchorEvent(ctx, actor, anchorRef, source, anchorEvent)
	if err != nil {
		return fmt.Errorf("handle anchor event: %w", err)
	}

	h.logger.Debug("Storing anchor reference", logfields.WithAnchorEventURI(anchorRef))

	err = h.store.AddReference(store.AnchorLinkset, anchorRef, h.ServiceIRI)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor reference: %w", err))
	}

	return nil
}

func (h *Inbox) handleAnchorEventReference(ctx context.Context, actor, anchorRef, source *url.URL) error {
	ok, err := h.hasReference(anchorRef, h.ServiceIRI, store.AnchorLinkset)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("has anchor event reference [%s]: %w",
			anchorRef, err))
	}

	if ok {
		return fmt.Errorf("handle anchor event [%s]: %w", anchorRef, service.ErrDuplicateAnchorEvent)
	}

	err = h.AnchorHandler.HandleAnchorEvent(ctx, actor, anchorRef, source, nil)
	if err != nil {
		return fmt.Errorf("handle anchor event: %w", err)
	}

	h.logger.Debug("Storing anchor event reference", logfields.WithAnchorEventURI(anchorRef))

	err = h.store.AddReference(store.AnchorLinkset, anchorRef, h.ServiceIRI)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor event reference: %w", err))
	}

	return nil
}

//nolint:cyclop
func (h *Inbox) handleAnnounceCollection(ctx context.Context, source *url.URL, announce *vocab.ActivityType,
	items []*vocab.ObjectProperty,
) (int, error) {
	var anchorURIs []*url.URL

	for _, item := range items {
		if !item.Type().Is(vocab.TypeAnchorEvent) {
			return 0, fmt.Errorf("expecting 'Info' type")
		}

		anchorEvent := item.AnchorEvent()

		if err := anchorEvent.Validate(); err != nil {
			// Continue processing other anchor events on invalid anchor event.
			h.logger.Info("Ignoring invalid anchor event", zap.String(logfields.FieldAnchorEventURI, anchorEvent.URL().String()))

			continue
		}

		if anchorEvent.Object() != nil { //nolint:nestif
			if err := h.handleAnchorEvent(ctx, announce.Actor(), source, anchorEvent); err != nil {
				// Continue processing other anchor events on duplicate error.
				if !errors.Is(err, service.ErrDuplicateAnchorEvent) {
					return 0, err
				}

				h.logger.Debug("Ignoring duplicate anchor event", logfields.WithAnchorEventURI(anchorEvent.URL()[0]))
			} else {
				anchorURIs = append(anchorURIs, anchorEvent.URL()[0])
			}
		} else {
			if err := h.handleAnchorEventReference(ctx, announce.Actor(), anchorEvent.URL()[0], source); err != nil {
				// Continue processing other anchor events on duplicate error.
				if !errors.Is(err, service.ErrDuplicateAnchorEvent) {
					return 0, err
				}

				h.logger.Debug("Ignoring duplicate anchor event", logfields.WithAnchorEventURI(anchorEvent.URL()[0]))
			} else {
				anchorURIs = append(anchorURIs, anchorEvent.URL()[0])
			}
		}
	}

	for _, anchorURI := range anchorURIs {
		h.logger.Debug("Adding 'Announce' activity to shares of anchor event",
			logfields.WithActivityID(announce.ID()), logfields.WithAnchorEventURI(anchorURI))

		err := h.store.AddReference(store.Share, anchorURI, announce.ID().URL())
		if err != nil {
			// This isn't a fatal error so just log a warning.
			h.logger.Warn("Error adding 'Announce' activity to 'shares' of anchor event",
				logfields.WithActivityID(announce.ID()), logfields.WithAnchorEventURI(anchorURI), log.WithError(err))
		}
	}

	return len(anchorURIs), nil
}

func (h *Inbox) handleLikeActivity(like *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Like' activity", logfields.WithActivityID(like.ID()))

	if err := h.validateLikeActivity(like); err != nil {
		return fmt.Errorf("invalid 'Like' activity [%s]: %w", like.ID(), err)
	}

	// TODO: Will there always be only one URL?
	refURL := like.Object().AnchorEvent().URL()[0]

	var additionalRefs []*url.URL

	if like.Result() != nil {
		additionalRefs = like.Result().AnchorEvent().URL()
	}

	if err := h.AnchorAckHandler.AnchorEventAcknowledged(like.Actor(), refURL, additionalRefs); err != nil {
		return fmt.Errorf("error creating result for 'Like' activity [%s]: %w", like.ID(), err)
	}

	h.logger.Debug("Adding anchor event to the 'Likes' collection", logfields.WithAnchorEventURI(refURL))

	if err := h.store.AddReference(store.Like, refURL, like.ID().URL()); err != nil {
		return orberrors.NewTransient(fmt.Errorf("add activity to 'Likes' collection: %w", err))
	}

	h.notify(like)

	return nil
}

func (h *Inbox) announceAnchorEvent(ctx context.Context, create *vocab.ActivityType) error {
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

	// Announce the activity to our followers but exclude the actor of the Create.
	if _, err := h.outbox.Post(ctx, announce, create.Actor()); err != nil {
		return orberrors.NewTransient(err)
	}

	return nil
}

func (h *Inbox) announceAnchorEventRef(ctx context.Context, create *vocab.ActivityType) error {
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

	activityID, err := h.outbox.Post(ctx, announce)
	if err != nil {
		return orberrors.NewTransient(err)
	}

	h.logger.Debug("Adding 'Announce' activity to the shares of anchor event",
		logfields.WithActivityID(announce.ID()), logfields.WithAnchorEventURI(anchorEventURL))

	err = h.store.AddReference(store.Share, anchorEventURL, activityID)
	if err != nil {
		h.logger.Warn("Error adding 'Announce' activity to 'shares' of anchor event",
			logfields.WithActivityID(announce.ID()), logfields.WithAnchorEventURI(anchorEventURL))
	}

	return nil
}

//nolint:cyclop
func (h *Inbox) validateAndUnmarshalOfferActivity(offer *vocab.ActivityType) (*linkset.Link, error) {
	if offer.StartTime() == nil {
		return nil, fmt.Errorf("startTime is required")
	}

	if offer.EndTime() == nil {
		return nil, fmt.Errorf("endTime is required")
	}

	if time.Now().After(*offer.EndTime()) {
		return nil, fmt.Errorf("offer [%s] has expired", offer.ID())
	}

	if offer.Target().IRI() == nil || offer.Target().IRI().String() != vocab.AnchorWitnessTargetIRI.String() {
		return nil, fmt.Errorf("object target IRI must be set to %s", vocab.AnchorWitnessTargetIRI)
	}

	anchorLinksetDoc := offer.Object().Document()
	if anchorLinksetDoc == nil {
		return nil, fmt.Errorf("object is required")
	}

	anchorLinkset := &linkset.Linkset{}

	if err := vocab.UnmarshalFromDoc(anchorLinksetDoc, anchorLinkset); err != nil {
		return nil, fmt.Errorf("unmarshal anchor Linkset: %w", err)
	}

	if len(anchorLinkset.Linkset) == 0 {
		return nil, fmt.Errorf("empty anchor Linkset")
	}

	anchorLink := anchorLinkset.Linkset[0]

	if err := anchorLink.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed for anchor link: %w", err)
	}

	replies := anchorLink.Replies()
	if replies == nil {
		return nil, fmt.Errorf("no replies in anchor Linkset")
	}

	if replies.Type() != linkset.TypeJSONLD {
		return nil, fmt.Errorf("unsupport reply type in anchor Linkset: %s", replies.Type())
	}

	return anchorLink, nil
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

	if err := like.Object().AnchorEvent().Validate(); err != nil {
		return fmt.Errorf("validate anchor event: %w", err)
	}

	return nil
}

func (h *Inbox) witnessAnchorCredential(vcBytes []byte) (*vocab.ObjectType, error) {
	response, err := h.Witness.Witness(vcBytes)
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

func (h *Inbox) undoFollowReference(activity *vocab.ActivityType,
	getTargetIRI func() *url.URL,
) error {
	err := h.undoAddReference(activity, store.Follower, getTargetIRI)
	if err != nil {
		return err
	}

	err = h.UndoFollowHandler.Undo(activity.Actor())
	if err != nil {
		return fmt.Errorf("undo follow for actor %s: %w", activity.Actor(), err)
	}

	return nil
}

func (h *Inbox) undoAddReference(activity *vocab.ActivityType, refType store.ReferenceType,
	getTargetIRI func() *url.URL,
) error {
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

	h.logger.Debug("Reference was successfully deleted", logfields.WithActorIRI(actorIRI),
		logfields.WithServiceIRI(h.ServiceIRI), logfields.WithReferenceType(string(refType)))

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

	h.logger.Debug("Anchor event was successfully deleted from the 'Likes' collection",
		logfields.WithActivityID(like.ID()), logfields.WithAnchorEventURI(u))

	// TODO: Will there always be only one URL?
	refURL := like.Object().AnchorEvent().URL()[0]

	var additionalRefs []*url.URL

	if like.Result() != nil {
		additionalRefs = like.Result().AnchorEvent().URL()
	}

	if err := h.AnchorAckHandler.UndoAnchorEventAcknowledgement(like.Actor(), refURL, additionalRefs); err != nil {
		return fmt.Errorf("error undoing 'Like' activity [%s]: %w", like.ID(), err)
	}

	return nil
}

func (h *Inbox) ensureActivityInOutbox(activity *vocab.ActivityType) (*vocab.ActivityType, error) {
	obActivity, err := h.getActivityFromOutbox(activity.ID().URL())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("get activity [%s] of type %s from outbox: %w",
				activity.ID(), activity.Type(), err)
		}

		return nil, orberrors.NewTransient(fmt.Errorf("get activity [%s] of type %s from outbox: %w",
			activity.ID(), activity.Type(), err))
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

	defer store2.CloseIterator(it)

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

func (p *noOpAnchorCredentialPublisher) HandleAnchorEvent(_ context.Context, _, _, _ *url.URL, _ *vocab.AnchorEventType) error {
	return nil
}

// AcceptAllActorsAuth is an authorization handler that accepts any actor.
type AcceptAllActorsAuth struct{}

// AuthorizeActor authorizes the actor. This implementation always returns true.
func (a *AcceptAllActorsAuth) AuthorizeActor(*vocab.ActorType) (bool, error) {
	return true, nil
}

type noOpProofHandler struct{}

func (p *noOpProofHandler) HandleProof(ctx context.Context, witness *url.URL, anchorID string, endTime time.Time, proof []byte) error {
	return nil
}

type noOpAnchorAcknowledgementHandler struct{}

func (p *noOpAnchorAcknowledgementHandler) AnchorEventAcknowledged(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL,
) error {
	logger.Debug("Anchor event was acknowledged by actor",
		logfields.WithActorIRI(actor), zap.String("anchor-event-uri", hashlink.ToString(anchorRef)),
		zap.String("additional-anchors", hashlink.ToString(additionalAnchorRefs...)))

	return nil
}

func (p *noOpAnchorAcknowledgementHandler) UndoAnchorEventAcknowledgement(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL,
) error {
	logger.Debug("Anchor event was undone by actor",
		logfields.WithActorIRI(actor), zap.String("anchor-event-uri", hashlink.ToString(anchorRef)),
		zap.String("additional-anchors", hashlink.ToString(additionalAnchorRefs...)))

	return nil
}
