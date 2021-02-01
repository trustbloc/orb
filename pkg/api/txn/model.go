/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txn

// Payload defines orb transaction details.
type Payload struct {
	AnchorString         string            `json:"anchorString"`
	Namespace            string            `json:"namespace"`
	Version              uint64            `json:"version"`
	PreviousTransactions map[string]string `json:"previousTransactions,omitempty"`
}
