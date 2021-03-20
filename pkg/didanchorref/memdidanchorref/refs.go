/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidanchorref

import (
	"sync"

	"github.com/trustbloc/orb/pkg/didanchorref"
)

// MemDidAnchorRef is in-memory implementation of did/anchor references.
type MemDidAnchorRef struct {
	sync.RWMutex
	m map[string][]string
}

// New creates in-memory implementation for did anchor references.
func New() *MemDidAnchorRef {
	return &MemDidAnchorRef{m: make(map[string][]string)}
}

// Add adds anchor cid to the list of anchor references that have been seen for this did.
func (ref *MemDidAnchorRef) Add(suffixes []string, cid string) error {
	ref.Lock()
	defer ref.Unlock()

	// update global did/anchor references
	for _, suffix := range suffixes {
		ref.m[suffix] = append(ref.m[suffix], cid)
	}

	return nil
}

// Get returns all anchor credential CIDs related to this suffix.
func (ref *MemDidAnchorRef) Get(suffix string) ([]string, error) {
	ref.RLock()
	defer ref.RUnlock()

	anchors, ok := ref.m[suffix]
	if !ok || len(anchors) == 0 {
		return nil, didanchorref.ErrDidAnchorsNotFound
	}

	return anchors, nil
}

// Last will return CID of the latest anchor credential for this suffix.
func (ref *MemDidAnchorRef) Last(suffix string) (string, error) {
	anchors, err := ref.Get(suffix)
	if err != nil {
		return "", err
	}

	return anchors[len(anchors)-1], nil
}
