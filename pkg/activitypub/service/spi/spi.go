/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"errors"
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
	Post(activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

// Inbox defines the functions for an ActivityPub inbox.
type Inbox interface {
	ServiceLifecycle
}

// AnchorEventHandler handles a new, published anchor event.
type AnchorEventHandler interface {
	HandleAnchorEvent(actor, anchorEventRef, source *url.URL, anchorEvent *vocab.AnchorEventType) error
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
	HandleProof(witness *url.URL, anchorID string, endTime time.Time, proof []byte) error
}

// ActivityHandler defines the functions of an Activity handler.
type ActivityHandler interface {
	ServiceLifecycle

	// HandleActivity handles the ActivityPub activity. An optional source may be added
	// to indicate where the activity was retrieved from.
	HandleActivity(source *url.URL, activity *vocab.ActivityType) error

	// Subscribe allows a client to receive published activities.
	Subscribe() <-chan *vocab.ActivityType
}

// ErrDuplicateAnchorEvent indicates that the anchor event was already processed by the InboxHandler.
var ErrDuplicateAnchorEvent = errors.New("anchor event already handled")

// InboxHandler defines functions for handling Create and Announce activities.
type InboxHandler interface {
	HandleCreateActivity(source *url.URL, create *vocab.ActivityType, announce bool) error
	HandleAnnounceActivity(source *url.URL, create *vocab.ActivityType) error
}

// UndeliverableActivityHandler handles undeliverable activities.
type UndeliverableActivityHandler interface {
	HandleUndeliverableActivity(activity *vocab.ActivityType, toURL string)
}

// Handlers contains handlers for various activity events, including undeliverable activities.
type Handlers struct {
	UndeliverableHandler  UndeliverableActivityHandler
	AnchorEventHandler    AnchorEventHandler
	FollowerAuth          ActorAuth
	WitnessInvitationAuth ActorAuth
	Witness               WitnessHandler
	ProofHandler          ProofHandler
	AnchorEventAckHandler AnchorEventAcknowledgementHandler
}

// HandlerOpt sets a specific handler.
type HandlerOpt func(options *Handlers)

// WithUndeliverableHandler sets the handler that's called when an activity can't be delivered.
func WithUndeliverableHandler(handler UndeliverableActivityHandler) HandlerOpt {
	return func(options *Handlers) {
		options.UndeliverableHandler = handler
	}
}

// WithAnchorEventHandler sets the handler for the published anchor event.
func WithAnchorEventHandler(handler AnchorEventHandler) HandlerOpt {
	return func(options *Handlers) {
		options.AnchorEventHandler = handler
	}
}

// WithFollowAuth sets the handler that decides whether or not to accept a 'Follow' request.
func WithFollowAuth(handler ActorAuth) HandlerOpt {
	return func(options *Handlers) {
		options.FollowerAuth = handler
	}
}

// WithInviteWitnessAuth sets the handler that decides whether or not to accept an 'InviteWitness' request.
func WithInviteWitnessAuth(handler ActorAuth) HandlerOpt {
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

// AcceptList contains the URIs that are to be accepted by an authorization handler
// for the given type. Known types are "follow" and "invite-witness".
type AcceptList struct {
	Type string
	URL  []*url.URL
}
