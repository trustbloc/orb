/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"fmt"

	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Outbox handles activities posted to the outbox.
type Outbox struct {
	*handler
}

// NewOutbox returns a new ActivityPub outbox activity handler.
func NewOutbox(cfg *Config, s store.Store, t httpTransport) *Outbox {
	h := &Outbox{}

	h.handler = newHandler(cfg, s, t,
		func(follow *vocab.ActivityType) error {
			return h.undoAddReference(follow, store.Following)
		},
	)

	return h
}

// HandleActivity handles the ActivityPub activity in the outbox.
func (h *Outbox) HandleActivity(activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeUndo):
		return h.handleUndoActivity(activity)
	default:
		// Nothing to do for activity.
		return nil
	}
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
		if err == store.ErrNotFound {
			logger.Infof("[%s] %s not found in %s collection of %s", h.ServiceName, iri, refType, h.ServiceIRI)

			return nil
		}

		return fmt.Errorf("unable to delete %s from %s's collection of %s", iri, h.ServiceIRI, refType)
	}

	logger.Debugf("[%s] %s was successfully deleted from %s's collection of %s",
		h.ServiceIRI, iri, h.ServiceIRI, refType)

	return nil
}
