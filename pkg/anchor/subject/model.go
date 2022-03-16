/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subject

// Payload defines orb anchor details.
type Payload struct {
	OperationCount  uint64
	CoreIndex       string
	Attachments     []string
	Namespace       string
	Version         uint64
	AnchorOrigin    string
	PreviousAnchors []*SuffixAnchor
}

// SuffixAnchor describes an anchor for suffix.
type SuffixAnchor struct {
	Suffix string
	Anchor string
}
