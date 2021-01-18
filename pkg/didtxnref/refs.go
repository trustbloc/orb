/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didtxnref

import (
	"errors"
)

// ErrDidTransactionReferencesNotFound is did transaction references not found error.
var ErrDidTransactionReferencesNotFound = errors.New("did transaction references not found")

// DidTransactionReferences manages did transaction references.
type DidTransactionReferences interface {
	Add(did, cid string) error
	Get(did string) ([]string, error)
}
