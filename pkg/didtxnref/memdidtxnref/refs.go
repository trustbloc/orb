/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memdidtxnref

import (
	"sync"

	"github.com/trustbloc/orb/pkg/didtxnref"
)

// MemDidTxnRef is in-memory implementation of did/txn references.
type MemDidTxnRef struct {
	sync.RWMutex
	m map[string][]string
}

// New creates in-memory implementation for did transaction references.
func New() *MemDidTxnRef {
	return &MemDidTxnRef{m: make(map[string][]string)}
}

// Add adds cid (transaction reference) to the list of transaction references that have been seen for this did.
func (ref *MemDidTxnRef) Add(suffix, cid string) error {
	ref.Lock()
	defer ref.Unlock()

	ref.m[suffix] = append(ref.m[suffix], cid)

	return nil
}

// Get returns all anchor credential CIDs related to this suffix.
func (ref *MemDidTxnRef) Get(suffix string) ([]string, error) {
	ref.RLock()
	defer ref.RUnlock()

	anchors, ok := ref.m[suffix]
	if !ok || len(anchors) == 0 {
		return nil, didtxnref.ErrDidTransactionsNotFound
	}

	return anchors, nil
}

// Last will return CID of the latest anchor credential for this suffix.
func (ref *MemDidTxnRef) Last(suffix string) (string, error) {
	anchors, err := ref.Get(suffix)
	if err != nil {
		return "", err
	}

	return anchors[len(anchors)-1], nil
}
