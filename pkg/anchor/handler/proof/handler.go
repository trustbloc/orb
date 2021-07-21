/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	proofapi "github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
)

var logger = log.New("proof-handler")

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

type vcPublisher interface {
	Publish(vc *verifiable.Credential) error
}

// New creates new proof handler.
func New(providers *Providers, pubSub pubSub) *WitnessProofHandler {
	return &WitnessProofHandler{
		Providers: providers,
		publisher: vcpubsub.NewPublisher(pubSub),
	}
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
	publisher vcPublisher
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

	serverTime := time.Now().Unix()

	if endTime.Unix() < serverTime {
		// proof came after expiry time so nothing to do here
		// clean up process for witness store and Sidetree batch files will have to be initiated differently
		// since we can have scenario that proof never shows up
		return nil
	}

	status, err := h.VCStatusStore.GetStatus(anchorCredID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor credential[%s]: %w", anchorCredID, err)
	}

	if status == proofapi.VCStatusCompleted {
		logger.Infof("Received proof from [%s] but witness policy has already been satisfied for anchorCredID[%s]",
			witness, anchorCredID, string(proof))

		// witness policy has been satisfied and witness proofs added to verifiable credential - nothing to do
		return nil
	}

	var witnessProof vct.Proof

	err = json.Unmarshal(proof, &witnessProof)
	if err != nil {
		return fmt.Errorf("failed to unmarshal incoming witness proof for anchor credential[%s]: %w", anchorCredID, err)
	}

	vc, err := h.VCStore.Get(anchorCredID)
	if err != nil {
		return fmt.Errorf("failed to retrieve anchor credential[%s]: %w", anchorCredID, err)
	}

	err = h.WitnessStore.AddProof(anchorCredID, witness.String(), proof)
	if err != nil {
		return fmt.Errorf("failed to add witness[%s] proof for credential[%s]: %w", witness.String(), anchorCredID, err)
	}

	err = h.setupMonitoring(witnessProof, vc, endTime)
	if err != nil {
		return fmt.Errorf("failed to setup monitoring for anchor credential[%s]: %w", anchorCredID, err)
	}

	return h.handleWitnessPolicy(vc)
}

func (h *WitnessProofHandler) setupMonitoring(wp vct.Proof, vc *verifiable.Credential, endTime time.Time) error {
	var created string
	if createdVal, ok := wp.Proof["created"].(string); ok {
		created = createdVal
	}

	createdTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return fmt.Errorf("parse created: %w", err)
	}

	var domain string
	if domainVal, ok := wp.Proof["domain"].(string); ok {
		domain = domainVal
	}

	return h.MonitoringSvc.Watch(vc, endTime, domain, createdTime)
}

func (h *WitnessProofHandler) handleWitnessPolicy(vc *verifiable.Credential) error {
	logger.Debugf("Handling witness policy for VC [%s]", vc.ID)

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
		logger.Infof("Witness policy has not been satisfied for VC [%s]. Waiting for other proofs.", vc.ID)

		return nil
	}

	// witness policy has been satisfied so add witness proofs to vc, set 'complete' status for vc
	// publish witnessed vc to batch writer channel for further processing
	logger.Infof("Witness policy has been satisfied for VC [%s]", vc.ID)

	vc, err = addProofs(vc, witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to add witness proofs: %w", err)
	}

	status, err := h.VCStatusStore.GetStatus(vc.ID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor credential[%s]: %w", vc.ID, err)
	}

	logger.Debugf("Current status for VC [%s] is [%s]", vc.ID, status)

	if status == proofapi.VCStatusCompleted {
		logger.Infof("VC status has already been marked as completed for [%s]", vc.ID)

		return nil
	}

	// Publish the VC before setting the status to completed since, if the publisher returns a transient error,
	// then this handler would be invoked on another server instance. So, we want the status to remain in-process,
	// otherwise the handler on the other instance would not publish the VC because it would think that is has
	// already been processed.
	logger.Debugf("Publishing VC [%s]", vc.ID)

	err = h.publisher.Publish(vc)
	if err != nil {
		return fmt.Errorf("publish credential[%s]: %w", vc.ID, err)
	}

	logger.Debugf("Setting status to [%s] for [%s]", proofapi.VCStatusCompleted, vc.ID)

	err = h.VCStatusStore.AddStatus(vc.ID, proofapi.VCStatusCompleted)
	if err != nil {
		return fmt.Errorf("failed to change status to 'completed' for credential[%s]: %w", vc.ID, err)
	}

	return nil
}

func addProofs(vc *verifiable.Credential, proofs []*proofapi.WitnessProof) (*verifiable.Credential, error) {
	for _, p := range proofs {
		if p.Proof != nil {
			var witnessProof vct.Proof

			err := json.Unmarshal(p.Proof, &witnessProof)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal stored witness proof for anchor credential[%s]: %w", vc.ID, err)
			}

			vc.Proofs = append(vc.Proofs, witnessProof.Proof)
		}
	}

	return vc, nil
}
