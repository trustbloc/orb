/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
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

// HandlerAnchorCredential stores the anchor credential or returns an error if it was set.
func (m *AnchorCredentialHandler) HandlerAnchorCredential(cid string, anchorCred []byte) error {
	if m.err != nil {
		return m.err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchorCreds[cid] = anchorCred

	return nil
}

// AnchorCred returns the anchor credential by ID or nil if it doesn't exist.
func (m *AnchorCredentialHandler) AnchorCred(cid string) []byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.anchorCreds[cid]
}
