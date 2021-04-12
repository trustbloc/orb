/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidanchor

import (
	"sync"
)

// DidAnchor is in-memory implementation of did/anchor references.
type DidAnchor struct {
	sync.RWMutex
	m map[string]string
}

// New creates in-memory implementation for latest did anchor.
func New() *DidAnchor {
	return &DidAnchor{m: make(map[string]string)}
}

// Put saves anchor cid for specified suffixes. If suffix already exists, anchor value will be overwritten.
func (ref *DidAnchor) Put(suffixes []string, cid string) error {
	ref.Lock()
	defer ref.Unlock()

	for _, suffix := range suffixes {
		ref.m[suffix] = cid
	}

	return nil
}

// Get retrieves anchors for specified suffixes.
func (ref *DidAnchor) Get(suffixes []string) ([]string, error) {
	ref.RLock()
	defer ref.RUnlock()

	anchors := make([]string, len(suffixes))

	for i, suffix := range suffixes {
		anchor, ok := ref.m[suffix]
		if !ok {
			anchors[i] = ""
		} else {
			anchors[i] = anchor
		}
	}

	return anchors, nil
}
