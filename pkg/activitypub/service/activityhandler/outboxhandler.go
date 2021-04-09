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

	h.handler = newHandler(cfg, s, t, h.undoFollowing)

	h.undoFollow = h.undoFollowing

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

func (h *Outbox) undoFollowing(follow *vocab.ActivityType) error {
	// Make sure that the actor IRI is this service. If not then ignore the message.
	if follow.Actor().String() != h.ServiceIRI.String() {
		logger.Infof("[%s] Not handling 'Undo' of follow activity %s since this service %s"+
			" is not the actor %s", h.ServiceName, follow.ID(), h.ServiceIRI, follow.Actor())

		return nil
	}

	iri := follow.Object().IRI()
	if iri == nil {
		return fmt.Errorf("no IRI specified in 'object' field of the 'Follow' activity")
	}

	err := h.store.DeleteReference(store.Following, h.ServiceIRI, iri)
	if err != nil {
		if err == store.ErrNotFound {
			logger.Infof("[%s] %s not found in following collection of %s", h.ServiceName, iri, h.ServiceIRI)

			return nil
		}

		return fmt.Errorf("unable to delete %s from %s's collection of following", iri, h.ServiceIRI)
	}

	logger.Debugf("[%s] %s was successfully deleted from %s's collection of following",
		h.ServiceIRI, iri, h.ServiceIRI)

	return nil
}
