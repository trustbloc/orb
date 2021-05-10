/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

// WitnessProof contains anchor credential witness proof.
type WitnessProof struct {
	Type    Type
	Witness string
	Proof   []byte
}

// Type defines valid values for witness type.
type Type string

const (

	// TypeBatch captures "batch" witness type.
	TypeBatch Type = "batch"

	// TypeSystem captures "system" witness type.
	TypeSystem Type = "witness"
)
