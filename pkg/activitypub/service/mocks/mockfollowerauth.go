/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// ActorAuth implements a mock actor authorization handler.
type ActorAuth struct {
	accept bool
	err    error
}

// NewActorAuth returns a mock actor authorization.
func NewActorAuth() *ActorAuth {
	return &ActorAuth{}
}

// WithAccept ensures that the request is accepted.
func (m *ActorAuth) WithAccept() *ActorAuth {
	m.accept = true

	return m
}

// WithReject ensures that the request is rejected.
func (m *ActorAuth) WithReject() *ActorAuth {
	m.accept = false

	return m
}

// WithError injects an error into the handler.
func (m *ActorAuth) WithError(err error) *ActorAuth {
	m.err = err

	return m
}

// AuthorizeActor is a mock implementation that returns the injected values.
func (m *ActorAuth) AuthorizeActor(follower *vocab.ActorType) (bool, error) {
	return m.accept, m.err
}
