/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

// ActivityPubClient is a mock ActivityPub client.
type ActivityPubClient struct {
	actors     map[string]*vocab.ActorType
	keys       map[string]*vocab.PublicKeyType
	activities []*vocab.ActivityType
	err        error
}

// NewActivitPubClient returns a mock ActivityPub client.
func NewActivitPubClient() *ActivityPubClient {
	return &ActivityPubClient{
		actors: make(map[string]*vocab.ActorType),
		keys:   make(map[string]*vocab.PublicKeyType),
	}
}

// WithPublicKey adds the given public key to the map of keys which is used
// by GetPublicKey.
func (m *ActivityPubClient) WithPublicKey(key *vocab.PublicKeyType) *ActivityPubClient {
	m.keys[key.ID().String()] = key

	return m
}

// WithActor adds the given actor to the map of actors which is used
// by GetActor.
func (m *ActivityPubClient) WithActor(actor *vocab.ActorType) *ActivityPubClient {
	m.actors[actor.ID().String()] = actor

	return m
}

// WithActivities sets the given activities to the slice of activities which is used by GetActivities.
func (m *ActivityPubClient) WithActivities(activities []*vocab.ActivityType) *ActivityPubClient {
	m.activities = activities

	return m
}

// WithError sets an error to be returned when any function is invoked on this struct.
func (m *ActivityPubClient) WithError(err error) *ActivityPubClient {
	m.err = err

	return m
}

// GetPublicKey returns the public key for the given IRI.
//nolint:interfacer
func (m *ActivityPubClient) GetPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error) {
	if m.err != nil {
		return nil, m.err
	}

	key, ok := m.keys[keyIRI.String()]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return key, nil
}

// GetActor returns the actor for the given IRI.
//nolint:interfacer
func (m *ActivityPubClient) GetActor(actorIRI *url.URL) (*vocab.ActorType, error) {
	if m.err != nil {
		return nil, m.err
	}

	actor, ok := m.actors[actorIRI.String()]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return actor, nil
}

// GetReferences simply returns an iterator that contains the IRI passed as an arg.
func (m *ActivityPubClient) GetReferences(iri *url.URL) (client.ReferenceIterator, error) {
	if m.err != nil {
		return nil, m.err
	}

	it := &ReferenceIterator{}
	it.NextReturnsOnCall(0, iri, nil)
	it.NextReturnsOnCall(1, nil, client.ErrNotFound)

	return it, nil
}

// GetActivities simply returns an iterator that contains the mock activities.
func (m *ActivityPubClient) GetActivities(iri *url.URL, _ client.Order) (client.ActivityIterator, error) {
	if m.err != nil {
		return nil, m.err
	}

	const pageSize = 3

	it := &ActivityIterator{}

	for i, a := range m.activities {
		it.NextReturnsOnCall(i, a, nil)

		it.CurrentPageReturnsOnCall(i, testutil.NewMockID(iri, fmt.Sprintf("&page-num=%d", i%pageSize)))
	}

	it.NextReturnsOnCall(len(m.activities), nil, client.ErrNotFound)

	return it, nil
}
