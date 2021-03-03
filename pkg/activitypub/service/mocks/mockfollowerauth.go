/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// FollowerAuth implements a mock follower authorization.
type FollowerAuth struct {
	accept bool
	err    error
}

// NewFollowerAuth returns a mock follower authorization.
func NewFollowerAuth() *FollowerAuth {
	return &FollowerAuth{}
}

// WithAccept ensures that the request to follow is accepted.
func (m *FollowerAuth) WithAccept() *FollowerAuth {
	m.accept = true

	return m
}

// WithReject ensures that the request to follow is rejected.
func (m *FollowerAuth) WithReject() *FollowerAuth {
	m.accept = false

	return m
}

// WithError injects an error into the handler.
func (m *FollowerAuth) WithError(err error) *FollowerAuth {
	m.err = err

	return m
}

// AuthorizeFollower is a mock implementation that returns the injected values.
func (m *FollowerAuth) AuthorizeFollower(follower *vocab.ActorType) (bool, error) {
	return m.accept, m.err
}
