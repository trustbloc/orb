/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidanchor

import (
	"sync"

	"github.com/trustbloc/orb/pkg/didanchor"
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

// PutBulk saves anchor cid for specified suffixes. If suffix already exists, anchor value will be overwritten.
func (ref *DidAnchor) PutBulk(suffixes []string, _ []bool, cid string) error {
	ref.Lock()
	defer ref.Unlock()

	for _, suffix := range suffixes {
		ref.m[suffix] = cid
	}

	return nil
}

// GetBulk retrieves anchors for specified suffixes.
func (ref *DidAnchor) GetBulk(suffixes []string) ([]string, error) {
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

// Get retrieves anchor for specified suffix.
func (ref *DidAnchor) Get(suffix string) (string, error) {
	ref.RLock()
	defer ref.RUnlock()

	anchor, ok := ref.m[suffix]
	if !ok {
		return "", didanchor.ErrDataNotFound
	}

	return anchor, nil
}
