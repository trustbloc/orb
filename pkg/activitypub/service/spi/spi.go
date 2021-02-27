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

// ActivityHandler defines the functions of an Activity handler.
type ActivityHandler interface {
	// HandleActivity handles the ActivityPub activity.
	HandleActivity(activity *vocab.ActivityType) error
}

// UndeliverableActivityHandler handles undeliverable activities.
type UndeliverableActivityHandler interface {
	HandleUndeliverableActivity(activity *vocab.ActivityType, toURL string)
}
