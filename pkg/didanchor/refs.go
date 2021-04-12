/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchor

// DidAnchor manages latest anchor for suffix.
type DidAnchor interface {
	Put(suffixes []string, cid string) error
	Get(suffixes []string) ([]string, error)
}
