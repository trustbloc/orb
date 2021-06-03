/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
	"sync"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

// Outbox implements a mock Outbox.
type Outbox struct {
	mutex      sync.RWMutex
	activities Activities
	err        error
	activityID *url.URL
}

// NewOutbox returns a mock outbox.
func NewOutbox() *Outbox {
	return &Outbox{}
}

// WithError injects an error into the mock outbox.
func (m *Outbox) WithError(err error) *Outbox {
	m.err = err

	return m
}

// WithActivityID sets the ID of the posted activity.
func (m *Outbox) WithActivityID(id *url.URL) *Outbox {
	m.activityID = id

	return m
}

// Activities returns the activities that were posted to the outbox.
func (m *Outbox) Activities() Activities {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.activities
}

// Post post an activity to the outbox. The activity is simply stored
// so that it may be retrieved by the Activies function.
func (m *Outbox) Post(activity *vocab.ActivityType) (*url.URL, error) {
	if m.err != nil {
		return nil, m.err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.activities = append(m.activities, activity)

	return m.activityID, nil
}

// Start does nothing.
func (m *Outbox) Start() {
}

// Stop does nothing.
func (m *Outbox) Stop() {
}

// State always returns StateStarted.
func (m *Outbox) State() lifecycle.State {
	return lifecycle.StateStarted
}
