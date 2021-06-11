/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchor

import "errors"

// DidAnchor manages latest anchor for suffix.
type DidAnchor interface {
	PutBulk(suffixes []string, cid string) error
	GetBulk(suffixes []string) ([]string, error)
	Get(suffix string) (string, error)
}

// ErrDataNotFound is used to indicate data not found error.
var ErrDataNotFound = errors.New("data not found")
