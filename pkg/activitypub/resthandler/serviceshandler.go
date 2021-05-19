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

// MainKeyID is the ID of the service's public key.
const MainKeyID = "main-key"

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

	h.handler = newHandler("", cfg, activityStore, h.handle, nil)

	return h
}

// NewPublicKeys returns a new public keys REST handler.
func NewPublicKeys(cfg *Config, activityStore spi.Store, publicKey *vocab.PublicKeyType) *Services {
	h := &Services{
		publicKey: publicKey,
	}

	h.handler = newHandler(PublicKeysPath, cfg, activityStore, h.handlePublicKey, nil)

	return h
}

func (h *Services) handle(w http.ResponseWriter, req *http.Request) {
	if !h.tokenVerifier.Verify(req) {
		h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

		return
	}

	s, err := h.newService()
	if err != nil {
		logger.Errorf("[%s] Invalid service configuration [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	serviceBytes, err := h.marshal(s)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal service [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.writeResponse(w, http.StatusOK, serviceBytes)
}

func (h *Services) handlePublicKey(w http.ResponseWriter, req *http.Request) {
	if !h.tokenVerifier.Verify(req) {
		h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

		return
	}

	keyID := getIDParam(req)

	if keyID == "" {
		logger.Infof("[%s] Key ID not specified [%s]", h.endpoint, h.ObjectIRI)

		h.writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	// Currently only one key is supported. In the future we may wish to have
	// multiple keys per service.
	if keyID != MainKeyID {
		logger.Infof("[%s] Public key [%s] not found for [%s]", h.endpoint, h.ObjectIRI, keyID)

		h.writeResponse(w, http.StatusNotFound, []byte(notFoundResponse))

		return
	}

	publicKeyBytes, err := h.marshal(h.publicKey)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal public key [%s]: %s", h.endpoint, h.ObjectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Returning public key bytes: %s", h.endpoint, publicKeyBytes)

	h.writeResponse(w, http.StatusOK, publicKeyBytes)
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
