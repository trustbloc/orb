/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"context"
	"net/url"
	"sync"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// AnchorEventHandler is a mock anchor event handler.
type AnchorEventHandler struct {
	mutex       sync.Mutex
	anchorCreds map[string]*vocab.AnchorEventType
	err         error
}

// NewAnchorEventHandler returns a mock anchor event handler.
func NewAnchorEventHandler() *AnchorEventHandler {
	return &AnchorEventHandler{
		anchorCreds: make(map[string]*vocab.AnchorEventType),
	}
}

// WithError injects an error into the mock handler.
func (m *AnchorEventHandler) WithError(err error) *AnchorEventHandler {
	m.err = err

	return m
}

// HandleAnchorEvent stores the anchor event or returns an error if it was set.
func (m *AnchorEventHandler) HandleAnchorEvent(ctx context.Context, actor, hl, source *url.URL, anchorEvent *vocab.AnchorEventType) error {
	if m.err != nil {
		return m.err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchorCreds[hl.String()] = anchorEvent

	return nil
}

// AnchorEvent returns the anchor credential by ID or nil if it doesn't exist.
func (m *AnchorEventHandler) AnchorEvent(hl string) (*vocab.AnchorEventType, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	value, ok := m.anchorCreds[hl]

	return value, ok
}
