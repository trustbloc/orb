/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
	"sync"
)

// AnchorCredentialHandler is a mock anchor credential handler.
type AnchorCredentialHandler struct {
	mutex       sync.Mutex
	anchorCreds map[string][]byte
	err         error
}

// NewAnchorCredentialHandler returns a mock anchor credential handler.
func NewAnchorCredentialHandler() *AnchorCredentialHandler {
	return &AnchorCredentialHandler{
		anchorCreds: make(map[string][]byte),
	}
}

// WithError injects an error into the mock handler.
func (m *AnchorCredentialHandler) WithError(err error) *AnchorCredentialHandler {
	m.err = err

	return m
}

// HandleAnchorCredential stores the anchor credential or returns an error if it was set.
func (m *AnchorCredentialHandler) HandleAnchorCredential(actor, id *url.URL, cid string, anchorCred []byte) error {
	if m.err != nil {
		return m.err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchorCreds[id.String()] = anchorCred

	return nil
}

// AnchorCred returns the anchor credential by ID or nil if it doesn't exist.
func (m *AnchorCredentialHandler) AnchorCred(id string) ([]byte, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	value, ok := m.anchorCreds[id]

	return value, ok
}
