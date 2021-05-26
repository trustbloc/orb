/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

// WitnessProof contains anchor credential witness proof.
type WitnessProof struct {
	Type    WitnessType
	Witness string
	Proof   []byte
}

// WitnessType defines valid values for witness type.
type WitnessType string

const (

	// WitnessTypeBatch captures "batch" witness type.
	WitnessTypeBatch WitnessType = "batch"

	// WitnessTypeSystem captures "system" witness type.
	WitnessTypeSystem WitnessType = "witness"
)

// VCStatus defines valid values for verifiable credential proof collection status.
type VCStatus string

const (

	// VCStatusInProcess defines "in-process" status.
	VCStatusInProcess VCStatus = "in-process"

	// VCStatusCompleted defines "completed" status.
	VCStatusCompleted VCStatus = "completed"
)
