/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

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
