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
func (ref *MemDidTxnRef) Add(did, cid string) error {
	ref.Lock()
	defer ref.Unlock()

	ref.m[did] = append(ref.m[did], cid)

	return nil
}

// Get returns transaction references for did.
func (ref *MemDidTxnRef) Get(did string) ([]string, error) {
	ref.RLock()
	defer ref.RUnlock()

	anchors, ok := ref.m[did]
	if !ok {
		return nil, didtxnref.ErrDidTransactionReferencesNotFound
	}

	if len(anchors) == 0 {
		return nil, didtxnref.ErrDidTransactionReferencesNotFound
	}

	return anchors, nil
}
