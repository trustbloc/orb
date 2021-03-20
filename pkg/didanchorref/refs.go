/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchorref

import (
	"errors"
)

// ErrDidAnchorsNotFound is did anchors not found error.
var ErrDidAnchorsNotFound = errors.New("did anchors not found")

// DidAnchorReferences manages did anchor references.
type DidAnchorReferences interface {
	Add(did, cid string) error
	Get(did string) ([]string, error)
}
