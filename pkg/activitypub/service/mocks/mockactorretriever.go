/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// ActorRetriever is a mock retriever for actors and public keys of actors.
type ActorRetriever struct {
	actors map[string]*vocab.ActorType
	keys   map[string]*vocab.PublicKeyType
}

// NewActorRetriever returns a mock actor retriever.
func NewActorRetriever() *ActorRetriever {
	return &ActorRetriever{
		actors: make(map[string]*vocab.ActorType),
		keys:   make(map[string]*vocab.PublicKeyType),
	}
}

// WithPublicKey adds the given public key to the map of keys which is used
// by GetPublicKey.
func (m *ActorRetriever) WithPublicKey(key *vocab.PublicKeyType) *ActorRetriever {
	m.keys[key.ID.String()] = key

	return m
}

// WithActor adds the given actor to the map of actors which is used
// by GetActor.
func (m *ActorRetriever) WithActor(actor *vocab.ActorType) *ActorRetriever {
	m.actors[actor.ID().String()] = actor

	return m
}

// GetPublicKey returns the public key for the given IRI.
//nolint:interfacer
func (m *ActorRetriever) GetPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error) {
	key, ok := m.keys[keyIRI.String()]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return key, nil
}

// GetActor returns the actor for the given IRI.
//nolint:interfacer
func (m *ActorRetriever) GetActor(actorIRI *url.URL) (*vocab.ActorType, error) {
	actor, ok := m.actors[actorIRI.String()]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return actor, nil
}
