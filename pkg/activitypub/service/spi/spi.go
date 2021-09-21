/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"net/url"
	"time"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

// ServiceLifecycle defines the functions of a service lifecycle.
type ServiceLifecycle interface {
	// Start starts the service.
	Start()
	// Stop stops the service.
	Stop()
	// State returns the state of the service.
	State() lifecycle.State
}

// Outbox defines the functions for an ActivityPub outbox.
type Outbox interface {
	ServiceLifecycle

	// Post posts an activity to the outbox and returns the ID of the activity.
	Post(activity *vocab.ActivityType) (*url.URL, error)
}

// Inbox defines the functions for an ActivityPub inbox.
type Inbox interface {
	ServiceLifecycle
}

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler interface {
	HandleAnchorCredential(actor, id *url.URL, cid string, anchorCred []byte) error
}

// AnchorEventAcknowledgementHandler handles notification of a successful anchor event processed from an Orb server,
// as well as undoing a previously acknowledged anchor event.
type AnchorEventAcknowledgementHandler interface {
	AnchorEventAcknowledged(actor, anchorRef *url.URL, additionalAnchorRefs []*url.URL) error
	UndoAnchorEventAcknowledgement(actor, anchorRef *url.URL, additionalAnchorRefs []*url.URL) error
}

// ActorAuth makes the decision of whether or not a request by the given
// actor should be accepted.
type ActorAuth interface {
	AuthorizeActor(actor *vocab.ActorType) (bool, error)
}

// WitnessHandler is a handler that witnesses an anchor credential.
type WitnessHandler interface {
	Witness(anchorCred []byte) ([]byte, error)
}

// ProofHandler handles the given proof for the anchor credential.
type ProofHandler interface {
	HandleProof(witness *url.URL, anchorCredID string, endTime time.Time, proof []byte) error
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
	FollowerAuth            ActorAuth
	WitnessInvitationAuth   ActorAuth
	Witness                 WitnessHandler
	ProofHandler            ProofHandler
	AnchorEventAckHandler   AnchorEventAcknowledgementHandler
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
func WithFollowerAuth(handler ActorAuth) HandlerOpt {
	return func(options *Handlers) {
		options.FollowerAuth = handler
	}
}

// WithWitnessInvitationAuth sets the handler that decides whether or not to accept an 'InviteWitness' request.
func WithWitnessInvitationAuth(handler ActorAuth) HandlerOpt {
	return func(options *Handlers) {
		options.WitnessInvitationAuth = handler
	}
}

// WithWitness sets the witness handler.
func WithWitness(handler WitnessHandler) HandlerOpt {
	return func(options *Handlers) {
		options.Witness = handler
	}
}

// WithProofHandler sets the proof handler.
func WithProofHandler(handler ProofHandler) HandlerOpt {
	return func(options *Handlers) {
		options.ProofHandler = handler
	}
}

// WithAnchorEventAcknowledgementHandler sets the handler for an acknowledgement of a successful anchor event
// that was processed by another Orb server.
func WithAnchorEventAcknowledgementHandler(handler AnchorEventAcknowledgementHandler) HandlerOpt {
	return func(options *Handlers) {
		options.AnchorEventAckHandler = handler
	}
}
