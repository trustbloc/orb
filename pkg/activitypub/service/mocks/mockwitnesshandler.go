/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"
)

// WitnessHandler implements a mock witness handler.
type WitnessHandler struct {
	mutex       sync.Mutex
	err         error
	proof       []byte
	anchorCreds [][]byte
}

// NewWitnessHandler returns a mock witness handler.
func NewWitnessHandler() *WitnessHandler {
	return &WitnessHandler{}
}

// WithProof sets the proof to be returned from the witness handler.
func (m *WitnessHandler) WithProof(proof []byte) *WitnessHandler {
	m.proof = proof

	return m
}

// WithError injects an error.
func (m *WitnessHandler) WithError(err error) *WitnessHandler {
	m.err = err

	return m
}

// Witness adds the anchor credential to a list that can be inspected using the AnchorCreds function
// and returns the injected proof/error.
func (m *WitnessHandler) Witness(anchorCred []byte) ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.anchorCreds = append(m.anchorCreds, anchorCred)

	return m.proof, m.err
}

// AnchorCreds returns all of the anchor credentials that were witnessed by this mock.
func (m *WitnessHandler) AnchorCreds() [][]byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.anchorCreds
}
