/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"errors"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// UndeliverableTopic is the topic to which to post undeliverable messages.
const UndeliverableTopic = "undeliverable"

// ErrNotStarted indicates that an attempt was made to invoke a service that has not been started
// or is still in the process of starting.
var ErrNotStarted = errors.New("service has not started")

// State is the state of the service.
type State = uint32

const (
	// StateNotStarted indicates that the service has not been started.
	StateNotStarted State = 0
	// StateStarting indicates that the service is in the process of starting.
	StateStarting State = 1
	// StateStarted indicates that the service has been started.
	StateStarted State = 2
	// StateStopped indicates that the service has been stopped.
	StateStopped State = 3
)

// ServiceLifecycle defines the functions of a service lifecycle.
type ServiceLifecycle interface {
	// Start starts the service.
	Start()
	// Stop stops the service.
	Stop()
	// State returns the state of the service.
	State() State
}

// Outbox defines the functions for an ActivityPub outbox.
type Outbox interface {
	ServiceLifecycle

	Post(activity *vocab.ActivityType) error
}

// Inbox defines the functions for an ActivityPub inbox.
type Inbox interface {
	ServiceLifecycle
}

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler interface {
	HandlerAnchorCredential(cid string, anchorCred []byte) error
}

// FollowerAuth makes the decision of whether or not a request by the given
// follower should be accepted.
type FollowerAuth interface {
	AuthorizeFollower(follower *vocab.ActorType) (bool, error)
}

// WitnessHandler is a handler that witnesses an anchor credential.
type WitnessHandler interface {
	Witness(anchorCred []byte) ([]byte, error)
}

// ActivityHandler defines the functions of an Activity handler.
type ActivityHandler interface {
	ServiceLifecycle

	// HandleActivity handles the ActivityPub activity.
	HandleActivity(activity *vocab.ActivityType) error

	// Subscribe allows a client to receive published activities.
	Subscribe() <-chan *vocab.ActivityType
}

// UndeliverableActivityHandler handles undeliverable activities.
type UndeliverableActivityHandler interface {
	HandleUndeliverableActivity(activity *vocab.ActivityType, toURL string)
}

// Handlers contains handlers for various activity events, including undeliverable activities.
type Handlers struct {
	UndeliverableHandler    UndeliverableActivityHandler
	AnchorCredentialHandler AnchorCredentialHandler
	FollowerAuth            FollowerAuth
	Witness                 WitnessHandler
}

// HandlerOpt sets a specific handler.
type HandlerOpt func(options *Handlers)

// WithUndeliverableHandler sets the handler that's called when an activity can't be delivered.
func WithUndeliverableHandler(handler UndeliverableActivityHandler) HandlerOpt {
	return func(options *Handlers) {
		options.UndeliverableHandler = handler
	}
}

// WithAnchorCredentialHandler sets the handler for the published anchor credentials.
func WithAnchorCredentialHandler(handler AnchorCredentialHandler) HandlerOpt {
	return func(options *Handlers) {
		options.AnchorCredentialHandler = handler
	}
}

// WithFollowerAuth sets the handler that decides whether or not to accept a 'Follow' request.
func WithFollowerAuth(handler FollowerAuth) HandlerOpt {
	return func(options *Handlers) {
		options.FollowerAuth = handler
	}
}

// WithWitness sets the witness handler.
func WithWitness(handler WitnessHandler) HandlerOpt {
	return func(options *Handlers) {
		options.Witness = handler
	}
}
