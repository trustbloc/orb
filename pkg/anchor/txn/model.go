/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txn

// Payload defines orb transaction details.
type Payload struct {
	OperationCount  uint64            `json:"operationCount"`
	CoreIndex       string            `json:"coreIndex"`
	Namespace       string            `json:"namespace"`
	Version         uint64            `json:"version"`
	PreviousAnchors map[string]string `json:"previousAnchors,omitempty"`
}
