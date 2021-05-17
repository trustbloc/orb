/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package info

import (
	"net/url"
)

// AnchorInfo represents a CID and a WebCASURL that can be used to fetch the CID.
type AnchorInfo struct {
	CID       string
	WebCASURL *url.URL
	Hint      string
}
