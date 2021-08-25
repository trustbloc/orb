/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
	"sync"
)

// AnchorEventNotificationHandler implements a mock anchor event notification handler.
type AnchorEventNotificationHandler struct {
	mutex   sync.Mutex
	err     error
	anchors []*url.URL
}

// NewAnchorEventNotificationHandler returns a mock witness handler.
func NewAnchorEventNotificationHandler() *AnchorEventNotificationHandler {
	return &AnchorEventNotificationHandler{}
}

// WithError injects an error.
func (m *AnchorEventNotificationHandler) WithError(err error) *AnchorEventNotificationHandler {
	m.err = err

	return m
}

// AnchorEventProcessed handles notification of a successful anchor event processed from an Orb server.
func (m *AnchorEventNotificationHandler) AnchorEventProcessed(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchors = append(m.anchors, anchorRef)

	return m.err
}

// Anchors returns the anchors that were added to this mock.
func (m *AnchorEventNotificationHandler) Anchors() []*url.URL {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.anchors
}
