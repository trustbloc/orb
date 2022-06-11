/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"fmt"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Witness contains info about witness.
type Witness struct {
	Type     WitnessType        `json:"type"`
	URI      *vocab.URLProperty `json:"uri"`
	HasLog   bool               `json:"hasLog"`
	Selected bool               `json:"selected"`
}

func (wf *Witness) String() string {
	return fmt.Sprintf("{type:%s, witness:%s, log:%t}", wf.Type, wf.URI, wf.HasLog)
}

// WitnessProof contains anchor index witness proof.
type WitnessProof struct {
	*Witness
	Proof []byte
}

func (wf *WitnessProof) String() string {
	return fmt.Sprintf("{type:%s, witness:%s, log:%t, proof:%s}", wf.Type, wf.URI, wf.HasLog, string(wf.Proof))
}

// WitnessType defines valid values for witness type.
type WitnessType string

const (

	// WitnessTypeBatch captures "batch" witness type.
	WitnessTypeBatch WitnessType = "batch"

	// WitnessTypeSystem captures "system" witness type.
	WitnessTypeSystem WitnessType = "system"
)

// AnchorIndexStatus defines valid values for verifiable credential proof collection status.
type AnchorIndexStatus string

const (

	// AnchorIndexStatusInProcess defines "in-process" status.
	AnchorIndexStatusInProcess AnchorIndexStatus = "in-process"

	// AnchorIndexStatusCompleted defines "completed" status.
	AnchorIndexStatusCompleted AnchorIndexStatus = "completed"
)
