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
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	proofapi "github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
)

var logger = log.New("proof-handler")

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

type anchorEventPublisher interface {
	Publish(anchorEvent *vocab.AnchorEventType) error
}

type metricsProvider interface {
	WitnessAnchorCredentialTime(duration time.Duration)
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
	AnchorEventStore anchorEventStore
	StatusStore      statusStore
	WitnessStore     witnessStore
	WitnessPolicy    witnessPolicy
	MonitoringSvc    monitoringSvc
	DocLoader        ld.DocumentLoader
	Metrics          metricsProvider
}

// WitnessProofHandler handles an anchor credential witness proof.
type WitnessProofHandler struct {
	*Providers
	publisher anchorEventPublisher
}

type witnessStore interface {
	AddProof(anchorID, witness string, p []byte) error
	Get(anchorID string) ([]*proofapi.WitnessProof, error)
}

type anchorEventStore interface {
	Get(id string) (*vocab.AnchorEventType, error)
}

type statusStore interface {
	AddStatus(anchorEventID string, status proofapi.VCStatus) error
	GetStatus(anchorEventID string) (proofapi.VCStatus, error)
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type witnessPolicy interface {
	Evaluate(witnesses []*proofapi.WitnessProof) (bool, error)
}

// HandleProof handles proof.
func (h *WitnessProofHandler) HandleProof(witness *url.URL, anchors string, endTime time.Time, proof []byte) error { //nolint:lll
	logger.Debugf("received request anchor event [%s] from witness[%s], proof: %s",
		anchors, witness.String(), string(proof))

	serverTime := time.Now().Unix()

	if endTime.Unix() < serverTime {
		// proof came after expiry time so nothing to do here
		// clean up process for witness store and Sidetree batch files will have to be initiated differently
		// since we can have scenario that proof never shows up
		return nil
	}

	status, err := h.StatusStore.GetStatus(anchors)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor event [%s]: %w", anchors, err)
	}

	if status == proofapi.VCStatusCompleted {
		logger.Infof("Received proof from [%s] but witness policy has already been satisfied for anchor event[%s]",
			witness, anchors, string(proof))

		// witness policy has been satisfied and witness proofs added to verifiable credential - nothing to do
		return nil
	}

	var witnessProof vct.Proof

	err = json.Unmarshal(proof, &witnessProof)
	if err != nil {
		return fmt.Errorf("failed to unmarshal incoming witness proof for anchor event [%s]: %w", anchors, err)
	}

	anchorEvent, err := h.AnchorEventStore.Get(anchors)
	if err != nil {
		return fmt.Errorf("failed to retrieve anchor anchor event [%s]: %w", anchors, err)
	}

	err = h.WitnessStore.AddProof(anchors, witness.String(), proof)
	if err != nil {
		return fmt.Errorf("failed to add witness[%s] proof for anchor event [%s]: %w", witness.String(), anchors, err)
	}

	vc, err := util.VerifiableCredentialFromAnchorEvent(anchorEvent,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.DocLoader),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor event: %w", err)
	}

	err = h.setupMonitoring(witnessProof, vc, endTime)
	if err != nil {
		return fmt.Errorf("failed to setup monitoring for anchor event [%s]: %w", anchors, err)
	}

	return h.handleWitnessPolicy(anchorEvent, vc)
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

func (h *WitnessProofHandler) handleWitnessPolicy(anchorEvent *vocab.AnchorEventType, vc *verifiable.Credential) error { //nolint:funlen,gocyclo,cyclop,lll
	anchorID := anchorEvent.Anchors().String()

	logger.Debugf("Handling witness policy for anchor event [%s]", anchorID)

	witnessProofs, err := h.WitnessStore.Get(anchorID)
	if err != nil {
		return fmt.Errorf("failed to get witness proofs for anchor event [%s]: %w", anchorID, err)
	}

	ok, err := h.WitnessPolicy.Evaluate(witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to evaluate witness policy for anchor event [%s]: %w", anchorID, err)
	}

	if !ok {
		// witness policy has not been satisfied - wait for other witness proofs to arrive ...
		logger.Infof("Witness policy has not been satisfied for anchor event [%s]. Waiting for other proofs.", anchorID)

		return nil
	}

	// witness policy has been satisfied so add witness proofs to anchor event, set 'complete' status for anchor event
	// publish witnessed anchor event to batch writer channel for further processing
	logger.Infof("Witness policy has been satisfied for anchor event [%s]", anchorID)

	vc, err = addProofs(vc, witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to add witness proofs: %w", err)
	}

	status, err := h.StatusStore.GetStatus(anchorID)
	if err != nil {
		return fmt.Errorf("failed to get status for anchor event [%s]: %w", anchorID, err)
	}

	logger.Debugf("Current status for VC [%s] is [%s]", anchorID)

	if status == proofapi.VCStatusCompleted {
		logger.Infof("VC status has already been marked as completed for [%s]", anchorID)

		return nil
	}

	// Publish the VC before setting the status to completed since, if the publisher returns a transient error,
	// then this handler would be invoked on another server instance. So, we want the status to remain in-process,
	// otherwise the handler on the other instance would not publish the VC because it would think that is has
	// already been processed.
	logger.Debugf("Publishing anchor event [%s]", anchorID)

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal anchor credential: %w", err)
	}

	witness, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return fmt.Errorf("create new object with document: %w", err)
	}

	anchorObj, err := anchorEvent.AnchorObject(anchorEvent.Anchors())
	if err != nil {
		return fmt.Errorf("get anchor object for [%s]: %w", anchorEvent.Anchors(), err)
	}

	witnessedAnchorObj, err := vocab.NewAnchorObject(
		anchorObj.Generator(),
		anchorObj.ContentObject(),
		witness,
	)
	if err != nil {
		return fmt.Errorf("create new anchor object: %w", err)
	}

	// Create a new anchor event with the updated verifiable credential (witness).
	anchorEvent = vocab.NewAnchorEvent(
		vocab.WithAttributedTo(anchorEvent.AttributedTo().URL()),
		vocab.WithAnchors(anchorEvent.Anchors()),
		vocab.WithPublishedTime(anchorEvent.Published()),
		vocab.WithParent(anchorEvent.Parent()...),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(witnessedAnchorObj))),
	)

	err = h.publisher.Publish(anchorEvent)
	if err != nil {
		return fmt.Errorf("publish credential[%s]: %w", anchorID, err)
	}

	logger.Debugf("Setting status to [%s] for [%s]", proofapi.VCStatusCompleted, anchorID)

	err = h.StatusStore.AddStatus(anchorID, proofapi.VCStatusCompleted)
	if err != nil {
		return fmt.Errorf("failed to change status to 'completed' for anchor event [%s]: %w", anchorID, err)
	}

	if vc.Issued != nil {
		h.Metrics.WitnessAnchorCredentialTime(time.Since(vc.Issued.Time))
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
