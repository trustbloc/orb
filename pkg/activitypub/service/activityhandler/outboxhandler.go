/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"fmt"

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
		func(follow *vocab.ActivityType) error {
			return h.undoAddReference(follow, store.Following)
		},
		func(inviteWitness *vocab.ActivityType) error {
			return h.undoAddReference(inviteWitness, store.Witness)
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
	default:
		// Nothing to do for activity.
		return nil
	}
}

func (h *handler) handleCreateActivity(create *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Create' activity: %s", h.ServiceName, create.ID())

	obj := create.Object()

	var target *vocab.ObjectProperty

	switch {
	case obj.Type().Is(vocab.TypeAnchorCredential, vocab.TypeVerifiableCredential):
		target = create.Target()

	case obj.Type().Is(vocab.TypeAnchorCredentialRef):
		target = obj.AnchorCredentialReference().Target()

	default:
		return fmt.Errorf("unsupported object type in 'Create' activity [%s]: %s", obj.Type(), create.ID())
	}

	logger.Debugf("[%s] Storing anchor credential reference [%s]", h.ServiceName, target.Object().ID())

	err := h.store.AddReference(store.AnchorCredential, target.Object().ID().URL(), h.ServiceIRI)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("store anchor credential reference: %w", err))
	}

	return nil
}

func (h *Outbox) undoAddReference(activity *vocab.ActivityType, refType store.ReferenceType) error {
	if activity.Actor().String() != h.ServiceIRI.String() {
		return fmt.Errorf("this service is not the actor for the 'Undo'")
	}

	iri := activity.Object().IRI()
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
