/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
)

var logger = log.New("proof-handler")

// New creates new proof handler.
func New(providers *Providers, vcChan chan *verifiable.Credential) *WitnessProofHandler {
	return &WitnessProofHandler{Providers: providers, vcCh: vcChan}
}

// Providers contains all of the providers required by the handler.
type Providers struct {
	Store         vcStore
	MonitoringSvc monitoringSvc
	DocLoader     ld.DocumentLoader
}

// WitnessProofHandler handles an anchor credential witness proof.
type WitnessProofHandler struct {
	*Providers
	vcCh chan *verifiable.Credential
}

type vcStore interface {
	Get(id string) (*verifiable.Credential, error)
}

type monitoringSvc interface {
	Watch(anchorCredID string, endTime time.Time, proof []byte) error
}

// HandleProof handles proof.
func (h *WitnessProofHandler) HandleProof(anchorCredID string, startTime, endTime time.Time, proof []byte) error {
	logger.Debugf("received request anchorCredID[%s], proof: %s", anchorCredID, string(proof))

	err := h.MonitoringSvc.Watch(anchorCredID, endTime, proof)
	if err != nil {
		return fmt.Errorf("failed to setup monitoring for anchor credential[%s]: %w", anchorCredID, err)
	}

	var witnessProof vct.Proof

	err = json.Unmarshal(proof, &witnessProof)
	if err != nil {
		return fmt.Errorf("failed to unmarshal witness proof for anchor credential[%s]: %w", anchorCredID, err)
	}

	vc, err := h.Store.Get(anchorCredID)
	if err != nil {
		return fmt.Errorf("failed to retrieve anchor credential[%s]: %w", anchorCredID, err)
	}

	if len(vc.Proofs) > 1 {
		// TODO: issue-322 (handle multiple proofs - our witness policy is currently 1)
		logger.Debugf("Credential[%s] has already been witnessed, nothing to do", vc.ID)

		return nil
	}

	vc.Proofs = append(vc.Proofs, witnessProof.Proof)

	h.vcCh <- vc

	return nil
}
