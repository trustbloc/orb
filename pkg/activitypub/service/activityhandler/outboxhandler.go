/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
)

// Outbox handles activities posted to the outbox.
type Outbox struct {
	*handler
}

// NewOutbox returns a new ActivityPub outbox activity handler.
func NewOutbox(cfg *Config, s store.Store, activityPubClient activityPubClient) *Outbox {
	h := &Outbox{}

	h.handler = newHandler(cfg, s, activityPubClient,
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Following, func() *url.URL {
				return activity.Object().IRI()
			})
		},
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Witness, func() *url.URL {
				return activity.Target().IRI()
			})
		},
		func(activity *vocab.ActivityType) error {
			return h.undoAddReference(activity, store.Liked, func() *url.URL {
				return activity.ID().URL()
			})
		},
	)

	return h
}

// HandleActivity handles the ActivityPub activity in the outbox.
func (h *Outbox) HandleActivity(ctx context.Context, source *url.URL, activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.handleCreateActivity(ctx, activity)
	case typeProp.Is(vocab.TypeUndo):
		return h.handleUndoActivity(ctx, activity)
	case typeProp.Is(vocab.TypeLike):
		return h.handleLikeActivity(ctx, activity)
	default:
		// Nothing to do for activity.
		return nil
	}
}

func (h *handler) handleCreateActivity(_ context.Context, create *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Create' activity", logfields.WithActivityID(create.ID()))

	obj := create.Object()

	if !obj.Type().Is(vocab.TypeAnchorEvent) {
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", obj.Type(), create.ID())
	}

	anchorEvent := obj.AnchorEvent()

	err := anchorEvent.Validate()
	if err != nil {
		return fmt.Errorf("validate anchor event: %w", err)
	}

	anchorLinkset := &linkset.Linkset{}

	err = vocab.UnmarshalFromDoc(anchorEvent.Object().Document(), anchorLinkset)
	if err != nil {
		return fmt.Errorf("unmarshal linkset: %w", err)
	}

	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return fmt.Errorf("empty Linkset")
	}

	err = anchorLink.Validate()
	if err != nil {
		return fmt.Errorf("invalid anchor link: %w", err)
	}

	h.logger.Debug("Storing anchor reference", logfields.WithAnchorURI(anchorLink.Anchor()))

	if err := h.store.AddReference(store.AnchorLinkset, anchorEvent.URL()[0], h.ServiceIRI); err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor reference: %w", err))
	}

	return nil
}

func (h *Outbox) undoAddReference(activity *vocab.ActivityType, refType store.ReferenceType,
	getTargetIRI func() *url.URL) error {
	if activity.Actor().String() != h.ServiceIRI.String() {
		return fmt.Errorf("this service is not the actor for the 'Undo'")
	}

	iri := getTargetIRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in 'object' field")
	}

	if err := h.store.DeleteReference(refType, h.ServiceIRI, iri); err != nil {
		return orberrors.NewTransient(fmt.Errorf("unable to delete %s from %s's collection of %s",
			iri, h.ServiceIRI, refType))
	}

	h.logger.Debug("Reference was successfully deleted from the collection of the given type",
		logfields.WithServiceIRI(h.ServiceIRI), logfields.WithURI(iri), logfields.WithReferenceType(string(refType)))

	return nil
}

func (h *handler) handleLikeActivity(_ context.Context, like *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Like' activity", logfields.WithActivityID(like.ID()))

	ref := like.Object().AnchorEvent()

	if ref == nil || len(ref.URL()) == 0 {
		return errors.New("no anchor reference URL in 'Like' activity")
	}

	h.logger.Debug("Storing anchor event reference in the 'Liked' collection", logfields.WithAnchorEventURI(ref.URL()))

	err := h.store.AddReference(store.Liked, h.ServiceIRI, ref.URL()[0])
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("add anchor reference to 'Liked' collection: %w", err))
	}

	return nil
}
