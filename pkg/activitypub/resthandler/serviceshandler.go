/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Services implements the 'services' REST handler to retrieve a given ActivityPub service (actor).
type Services struct {
	*handler

	publicKey *vocab.PublicKeyType
}

// NewServices returns a new 'services' REST handler.
func NewServices(cfg *Config, activityStore spi.Store, publicKey *vocab.PublicKeyType) *Services {
	h := &Services{
		publicKey: publicKey,
	}

	h.handler = newHandler("", cfg, activityStore, h.handle)

	return h
}

func (h *Services) handle(w http.ResponseWriter, _ *http.Request) {
	s, err := h.newService()
	if err != nil {
		logger.Errorf("[%s] Invalid service configuration [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	serviceBytes, err := h.marshal(s)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal service [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(w, http.StatusOK, serviceBytes)
}

func (h *Services) newService() (*vocab.ActorType, error) {
	inbox, err := newID(h.ObjectIRI, InboxPath)
	if err != nil {
		return nil, err
	}

	outbox, err := newID(h.ObjectIRI, OutboxPath)
	if err != nil {
		return nil, err
	}

	followers, err := newID(h.ObjectIRI, FollowersPath)
	if err != nil {
		return nil, err
	}

	following, err := newID(h.ObjectIRI, FollowingPath)
	if err != nil {
		return nil, err
	}

	witnesses, err := newID(h.ObjectIRI, WitnessesPath)
	if err != nil {
		return nil, err
	}

	witnessing, err := newID(h.ObjectIRI, WitnessingPath)
	if err != nil {
		return nil, err
	}

	liked, err := newID(h.ObjectIRI, LikedPath)
	if err != nil {
		return nil, err
	}

	return vocab.NewService(h.ObjectIRI,
		vocab.WithPublicKey(h.publicKey),
		vocab.WithInbox(inbox),
		vocab.WithOutbox(outbox),
		vocab.WithFollowers(followers),
		vocab.WithFollowing(following),
		vocab.WithWitnesses(witnesses),
		vocab.WithWitnessing(witnessing),
		vocab.WithLiked(liked),
	), nil
}

func newID(iri fmt.Stringer, path string) (*url.URL, error) {
	return url.Parse(iri.String() + path)
}
