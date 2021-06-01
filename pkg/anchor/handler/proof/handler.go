/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	proofapi "github.com/trustbloc/orb/pkg/anchor/proof"
)

var logger = log.New("proof-handler")

// New creates new proof handler.
func New(providers *Providers, vcChan chan *verifiable.Credential) *WitnessProofHandler {
	return &WitnessProofHandler{Providers: providers, vcCh: vcChan}
}

// Providers contains all of the providers required by the handler.
type Providers struct {
	VCStore       vcStore
	VCStatusStore vcStatusStore
	WitnessStore  witnessStore
	WitnessPolicy witnessPolicy
	MonitoringSvc monitoringSvc
	DocLoader     ld.DocumentLoader
}

// WitnessProofHandler handles an anchor credential witness proof.
type WitnessProofHandler struct {
	*Providers
	vcCh chan *verifiable.Credential
}

type witnessStore interface {
	AddProof(vcID, witness string, p []byte) error
	Get(vcID string) ([]*proofapi.WitnessProof, error)
}

type vcStore interface {
	Get(id string) (*verifiable.Credential, error)
}

type vcStatusStore interface {
	AddStatus(vcID string, status proofapi.VCStatus) error
	GetStatus(vcID string) (proofapi.VCStatus, error)
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type witnessPolicy interface {
	Evaluate(witnesses []*proofapi.WitnessProof) (bool, error)
}

// HandleProof handles proof.
func (h *WitnessProofHandler) HandleProof(witness *url.URL, anchorCredID string, endTime time.Time, proof []byte) error { //nolint:lll
	logger.Debugf("received request anchorCredID[%s] from witness[%s], proof: %s",
		anchorCredID, witness.String(), string(proof))

	status, err := h.VCStatusStore.GetStatus(anchorCredID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor credential[%s]: %w", anchorCredID, err)
	}

	if status == proofapi.VCStatusCompleted {
		// witness policy has been satisfied and witness proofs added to verifiable credential - nothing to do
		return nil
	}

	var witnessProof vct.Proof

	err = json.Unmarshal(proof, &witnessProof)
	if err != nil {
		return fmt.Errorf("failed to unmarshal witness proof for anchor credential[%s]: %w", anchorCredID, err)
	}

	createdTime, err := time.Parse(time.RFC3339, witnessProof.Proof["created"].(string))
	if err != nil {
		return fmt.Errorf("parse created: %w", err)
	}

	vc, err := h.VCStore.Get(anchorCredID)
	if err != nil {
		return fmt.Errorf("failed to retrieve anchor credential[%s]: %w", anchorCredID, err)
	}

	err = h.MonitoringSvc.Watch(vc, endTime, witnessProof.Proof["domain"].(string), createdTime)
	if err != nil {
		return fmt.Errorf("failed to setup monitoring for anchor credential[%s]: %w", anchorCredID, err)
	}

	err = h.WitnessStore.AddProof(anchorCredID, witness.String(), proof)
	if err != nil {
		return fmt.Errorf("failed to add witness[%s] proof for credential[%s]: %w", witness.String(), anchorCredID, err)
	}

	return h.handleWitnessPolicy(vc)
}

func (h *WitnessProofHandler) handleWitnessPolicy(vc *verifiable.Credential) error {
	witnessProofs, err := h.WitnessStore.Get(vc.ID)
	if err != nil {
		return fmt.Errorf("failed to get witness proofs for credential[%s]: %w", vc.ID, err)
	}

	ok, err := h.WitnessPolicy.Evaluate(witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to evaluate witness policy for credential[%s]: %w", vc.ID, err)
	}

	if !ok {
		// witness policy has not been satisfied - wait for other witness proofs to arrive ...
		return nil
	}

	// witness policy has been satisfied so add witness proofs to vc, set 'complete' status for vc
	// publish witnessed vc to batch writer channel for further processing

	vc, err = addProofs(vc, witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to add witness proofs to credential[%s]: %w", vc.ID, err)
	}

	status, err := h.VCStatusStore.GetStatus(vc.ID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor credential[%s]: %w", vc.ID, err)
	}

	if status != proofapi.VCStatusCompleted {
		err := h.VCStatusStore.AddStatus(vc.ID, proofapi.VCStatusCompleted)
		if err != nil {
			return fmt.Errorf("failed to change status to 'completed' for credential[%s]: %w", vc.ID, err)
		}

		// TODO: we may have synchronisation issues here
		h.vcCh <- vc
	}

	return nil
}

func addProofs(vc *verifiable.Credential, proofs []*proofapi.WitnessProof) (*verifiable.Credential, error) {
	for _, p := range proofs {
		var witnessProof vct.Proof

		err := json.Unmarshal(p.Proof, &witnessProof)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal witness proof for anchor credential[%s]: %w", vc.ID, err)
		}

		vc.Proofs = append(vc.Proofs, witnessProof.Proof)
	}

	return vc, nil
}
