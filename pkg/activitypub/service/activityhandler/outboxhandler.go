/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"errors"
	"fmt"
	"net/url"

	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
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
func (h *Outbox) HandleActivity(activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.handleCreateActivity(activity)
	case typeProp.Is(vocab.TypeUndo):
		return h.handleUndoActivity(activity)
	case typeProp.Is(vocab.TypeLike):
		return h.handleLikeActivity(activity)
	default:
		// Nothing to do for activity.
		return nil
	}
}

func (h *handler) handleCreateActivity(create *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Create' activity: %s", h.ServiceName, create.ID())

	obj := create.Object()

	if !obj.Type().Is(vocab.TypeAnchorEvent) {
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", obj.Type(), create.ID())
	}

	anchorEvent := obj.AnchorEvent()

	if err := anchorEvent.Validate(); err != nil {
		return fmt.Errorf("invalid anchor event: %w", err)
	}

	if len(anchorEvent.URL()) == 0 {
		return errors.New("missing anchor event URL")
	}

	logger.Debugf("[%s] Storing anchor event reference [%s]", h.ServiceName, anchorEvent.URL())

	if err := h.store.AddReference(store.AnchorEvent, anchorEvent.URL()[0], h.ServiceIRI); err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor event reference: %w", err))
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

	logger.Debugf("[%s] %s (if found) was successfully deleted from %s's collection of %s",
		h.ServiceIRI, iri, h.ServiceIRI, refType)

	return nil
}

func (h *handler) handleLikeActivity(like *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Like' activity: %s", h.ServiceName, like.ID())

	ref := like.Object().AnchorEvent()

	if ref == nil || len(ref.URL()) == 0 {
		return errors.New("no anchor reference URL in 'Like' activity")
	}

	logger.Debugf("[%s] Storing anchor reference in the 'Liked' collection: %s", h.ServiceName, ref.URL())

	err := h.store.AddReference(store.Liked, h.ServiceIRI, ref.URL()[0])
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("add anchor reference to 'Liked' collection: %w", err))
	}

	return nil
}
