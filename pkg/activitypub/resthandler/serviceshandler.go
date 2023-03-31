/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
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
func NewServices(cfg *Config, activityStore spi.Store, publicKey *vocab.PublicKeyType,
	tm authTokenManager,
) *Services {
	h := &Services{
		publicKey: publicKey,
	}

	h.handler = newHandler("", cfg, activityStore, h.handle, nil, spi.SortAscending, tm)

	return h
}

// NewPublicKeys returns a new public keys REST handler.
func NewPublicKeys(cfg *Config, activityStore spi.Store, publicKey *vocab.PublicKeyType,
	tm authTokenManager,
) *Services {
	h := &Services{
		publicKey: publicKey,
	}

	h.handler = newHandler(PublicKeysPath, cfg, activityStore, h.handlePublicKey, nil, spi.SortAscending, tm)

	return h
}

func (h *Services) handle(w http.ResponseWriter, req *http.Request) {
	if !h.tokenVerifier.Verify(req) {
		h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

		return
	}

	s, err := h.newService()
	if err != nil {
		h.logger.Error("Invalid service configuration", logfields.WithObjectIRI(h.ObjectIRI), log.WithError(err))

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	serviceBytes, err := h.marshal(s)
	if err != nil {
		h.logger.Error("Unable to marshal service", logfields.WithObjectIRI(h.ObjectIRI), log.WithError(err))

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
		h.logger.Info("Key ID not specified", logfields.WithObjectIRI(h.ObjectIRI))

		h.writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	if fmt.Sprintf("%s/keys/%s", h.ObjectIRI, keyID) != h.publicKey.ID().String() {
		h.logger.Info("Public key not found", logfields.WithObjectIRI(h.ObjectIRI), logfields.WithKeyID(keyID))

		h.writeResponse(w, http.StatusNotFound, []byte(notFoundResponse))

		return
	}

	publicKeyBytes, err := h.marshal(h.publicKey)
	if err != nil {
		h.logger.Error("Unable to marshal public key", logfields.WithObjectIRI(h.ObjectIRI), log.WithError(err))

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.logger.Debug("Returning public key bytes", log.WithResponse(publicKeyBytes))

	h.writeResponse(w, http.StatusOK, publicKeyBytes)
}

func (h *Services) newService() (*vocab.ActorType, error) {
	inbox, err := newID(h.ServiceEndpointURL, InboxPath)
	if err != nil {
		return nil, err
	}

	outbox, err := newID(h.ServiceEndpointURL, OutboxPath)
	if err != nil {
		return nil, err
	}

	followers, err := newID(h.ServiceEndpointURL, FollowersPath)
	if err != nil {
		return nil, err
	}

	following, err := newID(h.ServiceEndpointURL, FollowingPath)
	if err != nil {
		return nil, err
	}

	witnesses, err := newID(h.ServiceEndpointURL, WitnessesPath)
	if err != nil {
		return nil, err
	}

	witnessing, err := newID(h.ServiceEndpointURL, WitnessingPath)
	if err != nil {
		return nil, err
	}

	liked, err := newID(h.ServiceEndpointURL, LikedPath)
	if err != nil {
		return nil, err
	}

	likes, err := newID(h.ServiceEndpointURL, LikesPath)
	if err != nil {
		return nil, err
	}

	shares, err := newID(h.ServiceEndpointURL, SharesPath)
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
		vocab.WithLikes(likes),
		vocab.WithShares(shares),
	), nil
}

func newID(iri fmt.Stringer, path string) (*url.URL, error) {
	return url.Parse(iri.String() + path)
}
