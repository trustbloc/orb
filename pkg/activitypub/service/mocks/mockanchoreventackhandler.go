/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
	"sync"
)

// AnchorEventAcknowledgementHandler implements a mock anchor event acknowledgement handler.
type AnchorEventAcknowledgementHandler struct {
	mutex   sync.Mutex
	err     error
	anchors []*url.URL
}

// NewAnchorEventAcknowledgementHandler returns a mock handler.
func NewAnchorEventAcknowledgementHandler() *AnchorEventAcknowledgementHandler {
	return &AnchorEventAcknowledgementHandler{}
}

// WithError injects an error.
func (m *AnchorEventAcknowledgementHandler) WithError(err error) *AnchorEventAcknowledgementHandler {
	m.err = err

	return m
}

// AnchorEventAcknowledged handles the acknowledgement of a successful anchor event processed from an Orb server.
func (m *AnchorEventAcknowledgementHandler) AnchorEventAcknowledged(actor, anchorRef *url.URL,
	additionalAnchorRefs []*url.URL) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchors = append(m.anchors, anchorRef)

	return m.err
}

// Anchors returns the anchors that were added to this mock.
func (m *AnchorEventAcknowledgementHandler) Anchors() []*url.URL {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.anchors
}
