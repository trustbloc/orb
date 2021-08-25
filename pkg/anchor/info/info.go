/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package info

// AnchorInfo represents a hashlink that can be used to fetch the anchor.
type AnchorInfo struct {
	Hashlink     string `json:"hashLink"`
	AttributedTo string `json:"attributedTo,omitempty"`
}
