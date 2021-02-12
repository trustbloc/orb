/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didtxnref

import (
	"errors"
)

// ErrDidTransactionsNotFound is did transactions not found error.
var ErrDidTransactionsNotFound = errors.New("did transactions not found")

// DidTransactionReferences manages did transaction references.
type DidTransactionReferences interface {
	Add(did, cid string) error
	Get(did string) ([]string, error)
}
