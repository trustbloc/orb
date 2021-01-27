/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txn

// OrbTransaction defines transaction information.
type OrbTransaction struct {
	Payload Payload `json:"payload"`
}

// Payload defines orb transaction payload (pre-announce payload).
type Payload struct {
	AnchorString   string            `json:"anchorString"`
	Namespace      string            `json:"namespace"`
	Version        uint64            `json:"version"`
	PreviousDidTxn map[string]string `json:"previousDidTransaction"`
}
