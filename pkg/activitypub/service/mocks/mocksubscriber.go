/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Subscriber implements a mock activity subscriber.
type Subscriber struct {
	activityChan <-chan *vocab.ActivityType
	mutex        sync.Mutex
	activities   []*vocab.ActivityType
}

// NewSubscriber returns a new mock activity subscriber.
func NewSubscriber(activityChan <-chan *vocab.ActivityType) *Subscriber {
	s := &Subscriber{
		activityChan: activityChan,
	}

	go s.listen()

	return s
}

// Activities returns the activities that were received by the subscriber.
func (m *Subscriber) Activities() []*vocab.ActivityType {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.activities
}

func (m *Subscriber) listen() {
	for activity := range m.activityChan {
		m.add(activity)
	}
}

func (m *Subscriber) add(activity *vocab.ActivityType) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.activities = append(m.activities, activity)
}
