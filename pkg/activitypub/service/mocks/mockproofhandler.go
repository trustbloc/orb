/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"context"
	"net/url"
	"sync"
	"time"
)

// ProofHandler implements a mock proof handler.
type ProofHandler struct {
	mutex  sync.Mutex
	proofs map[string][]byte
	err    error
}

// NewProofHandler returns a mock proof handler.
func NewProofHandler() *ProofHandler {
	return &ProofHandler{
		proofs: make(map[string][]byte),
	}
}

// WithError injects an error.
func (m *ProofHandler) WithError(err error) *ProofHandler {
	m.err = err

	return m
}

// HandleProof store the proof and returns any injected error.
func (m *ProofHandler) HandleProof(ctx context.Context, witness *url.URL, anchorCredID string, endTime time.Time, proof []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.proofs[anchorCredID] = proof

	return m.err
}

// Proof returns the stored proof for the givin ID.
func (m *ProofHandler) Proof(objID string) []byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.proofs[objID]
}
