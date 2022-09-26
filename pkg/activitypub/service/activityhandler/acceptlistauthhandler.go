/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.NewStructured(loggerModule)

const (
	// FollowType defines the 'follow' accept list type.
	FollowType = "follow"
	// InviteWitnessType defines the 'invite-witness' accept list type.
	InviteWitnessType = "invite-witness"
)

type acceptListMgr interface {
	Get(target string) ([]*url.URL, error)
}

// AcceptListAuthHandler implements an authorization handler that looks up an actor URI from an 'accept list'.
// If the actor URI is included in the accept list then the request is approved, otherwise it is denied.
type AcceptListAuthHandler struct {
	allowType string
	mgr       acceptListMgr
}

// NewAcceptListAuthHandler returns a new accept list authorization handler.
func NewAcceptListAuthHandler(allowType string, mgr acceptListMgr) *AcceptListAuthHandler {
	return &AcceptListAuthHandler{
		allowType: allowType,
		mgr:       mgr,
	}
}

// AuthorizeActor return true if the given actor is authorized.
func (h *AcceptListAuthHandler) AuthorizeActor(actor *vocab.ActorType) (bool, error) {
	allowList, err := h.mgr.Get(h.allowType)
	if err != nil {
		return false, fmt.Errorf("load accept list: %w", err)
	}

	if contains(allowList, actor.ID().URL()) {
		logger.Debug("Actor is in the accept list for the given type",
			log.WithActorID(actor.ID().String()), log.WithAcceptListType(h.allowType))

		return true, nil
	}

	logger.Debug("Actor is NOT in the accept-list for the given type",
		log.WithActorID(actor.ID().String()), log.WithAcceptListType(h.allowType))

	return false, nil
}

func contains(arr []*url.URL, uri *url.URL) bool {
	for _, s := range arr {
		if s.String() == uri.String() {
			return true
		}
	}

	return false
}
