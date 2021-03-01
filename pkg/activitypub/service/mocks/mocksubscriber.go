/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// MockSubscriber implements a mock activity subscriber.
type MockSubscriber struct {
	serviceName  string
	activityChan <-chan *vocab.ActivityType
	mutex        sync.Mutex
	activities   []*vocab.ActivityType
}

// NewMockSubscriber returns a new mock activity subscriber.
func NewMockSubscriber(
	serviceName string, activityChan <-chan *vocab.ActivityType) *MockSubscriber {
	s := &MockSubscriber{
		serviceName:  serviceName,
		activityChan: activityChan,
	}

	go s.listen()

	return s
}

// Activities returns the activities that were received by the subscriber.
func (m *MockSubscriber) Activities() []*vocab.ActivityType {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.activities
}

func (m *MockSubscriber) listen() {
	for activity := range m.activityChan {
		m.add(activity)
	}
}

func (m *MockSubscriber) add(activity *vocab.ActivityType) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.activities = append(m.activities, activity)
}
