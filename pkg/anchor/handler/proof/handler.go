/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
	proofapi "github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/datauri"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/vct"
)

var logger = log.New("proof-handler")

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
}

type anchorLinkPublisher interface {
	Publish(ctx context.Context, anchorLinkset *linkset.Linkset) error
}

type metricsProvider interface {
	WitnessAnchorCredentialTime(duration time.Duration)
}

// New creates new proof handler.
func New(providers *Providers, pubSub pubSub, dataURIMediaType datauri.MediaType, maxClockSkew time.Duration) *WitnessProofHandler {
	return &WitnessProofHandler{
		Providers:        providers,
		publisher:        vcpubsub.NewPublisher(pubSub),
		dataURIMediaType: dataURIMediaType,
		maxClockSkew:     maxClockSkew,
	}
}

// Providers contains the providers required by the handler.
type Providers struct {
	AnchorLinkStore anchorEventStore
	StatusStore     statusStore
	WitnessStore    witnessStore
	WitnessPolicy   witnessPolicy
	MonitoringSvc   monitoringSvc
	DocLoader       ld.DocumentLoader
	Metrics         metricsProvider
}

// WitnessProofHandler handles an anchor credential witness proof.
type WitnessProofHandler struct {
	*Providers
	publisher        anchorLinkPublisher
	dataURIMediaType vocab.MediaType
	maxClockSkew     time.Duration
}

type witnessStore interface {
	AddProof(anchorID string, witness *url.URL, p []byte) error
	Get(anchorID string) ([]*proofapi.WitnessProof, error)
}

type anchorEventStore interface {
	Get(id string) (*linkset.Link, error)
}

type statusStore interface {
	AddStatus(anchorEventID string, status proofapi.AnchorIndexStatus) error
	GetStatus(anchorEventID string) (proofapi.AnchorIndexStatus, error)
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type witnessPolicy interface {
	Evaluate(witnesses []*proofapi.WitnessProof) (bool, error)
}

// HandleProof handles proof.
func (h *WitnessProofHandler) HandleProof(ctx context.Context, witness *url.URL, anchor string, endTime time.Time, proof []byte) error {
	logger.Debug("Received proof for anchor from witness", logfields.WithAnchorURIString(anchor),
		logfields.WithActorIRI(witness), logfields.WithProof(proof))

	var witnessProof vct.Proof

	err := json.Unmarshal(proof, &witnessProof)
	if err != nil {
		return fmt.Errorf("failed to unmarshal incoming witness proof for anchor [%s]: %w", anchor, err)
	}

	anchorLink, err := h.AnchorLinkStore.Get(anchor)
	if err != nil {
		return fmt.Errorf("failed to retrieve anchor link [%s]: %w", anchor, err)
	}

	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLink,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.DocLoader),
		verifiable.WithStrictValidation(),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor: %w", err)
	}

	vcIssuedTime := vc.Issued.Time

	proofCreatedTime, err := getCreatedTime(witnessProof)
	if err != nil {
		return fmt.Errorf("failed to get create time from witness[%s] proof for anchor[%s] : %w",
			witness.String(), anchor, err)
	}

	endTimeForProof := endTime.Add(h.maxClockSkew)
	startTimeForProof := vcIssuedTime.Add(-1 * h.maxClockSkew)

	if proofCreatedTime.Before(startTimeForProof) || proofCreatedTime.After(endTimeForProof) {
		// proof created time is after expiry time or before create time so nothing to do here
		// clean up process for witness store and Sidetree batch files will have to be initiated differently
		// since we can have scenario that proof never shows up
		logger.Info("Proof created time for anchor from witness is either too early or too late.",
			logfields.WithCreatedTime(proofCreatedTime), logfields.WithAnchorURIString(anchor), logfields.WithActorIRI(witness))

		return nil
	}

	status, err := h.StatusStore.GetStatus(anchor)
	if err != nil {
		if !errors.Is(err, orberrors.ErrContentNotFound) {
			return fmt.Errorf("failed to get status for anchor [%s]: %w", anchor, err)
		}
	}

	if status == proofapi.AnchorIndexStatusCompleted {
		logger.Info("Received proof for anchor from witness but witness policy has already "+
			"been satisfied so it will be ignored.", logfields.WithAnchorURIString(anchor),
			logfields.WithActorIRI(witness), logfields.WithProof(proof))

		// witness policy has been satisfied and witness proofs added to verifiable credential - nothing to do
		return nil
	}

	err = h.WitnessStore.AddProof(anchor, witness, proof)
	if err != nil {
		return fmt.Errorf("failed to add witness[%s] proof for anchor [%s]: %w",
			witness.String(), anchor, err)
	}

	return h.handleWitnessPolicy(ctx, anchorLink, vc)
}

func getCreatedTime(wp vct.Proof) (time.Time, error) {
	var created string
	if createdVal, ok := wp.Proof["created"].(string); ok {
		created = createdVal
	}

	createdTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse created: %w", err)
	}

	return createdTime, nil
}

//nolint:cyclop
func (h *WitnessProofHandler) handleWitnessPolicy(ctx context.Context, anchorLink *linkset.Link, vc *verifiable.Credential) error {
	anchorID := anchorLink.Anchor().String()

	logger.Debug("Handling witness policy for anchor link", logfields.WithAnchorURIString(anchorID))

	witnessProofs, err := h.WitnessStore.Get(anchorID)
	if err != nil {
		return fmt.Errorf("failed to get witness proofs for anchor [%s]: %w", anchorID, err)
	}

	ok, err := h.WitnessPolicy.Evaluate(witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to evaluate witness policy for anchor [%s]: %w", anchorID, err)
	}

	if !ok {
		// Witness policy has not been satisfied - wait for other witness proofs to arrive ...
		logger.Info("Witness policy has not been satisfied for anchor. Waiting for other proofs.",
			logfields.WithAnchorURIString(anchorID))

		return nil
	}

	// Witness policy has been satisfied so add witness proofs to anchor, set 'complete' status for anchor
	// publish witnessed anchor to batch writer channel for further processing
	logger.Info("Witness policy has been satisfied for anchor", logfields.WithAnchorURIString(anchorID),
		logfields.WithVerifiableCredentialID(vc.ID))

	vc, err = addProofs(vc, witnessProofs)
	if err != nil {
		return fmt.Errorf("failed to add witness proofs: %w", err)
	}

	status, err := h.StatusStore.GetStatus(anchorID)
	if err != nil {
		if !errors.Is(err, orberrors.ErrContentNotFound) {
			return fmt.Errorf("failed to get status for anchor [%s]: %w", anchorID, err)
		}
	}

	if status == proofapi.AnchorIndexStatusCompleted {
		logger.Info("Anchor status has already been marked as completed for", logfields.WithAnchorURIString(anchorID),
			logfields.WithVerifiableCredentialID(vc.ID))

		return nil
	}

	// Publish the VC before setting the status to completed since, if the publisher returns a transient error,
	// then this handler would be invoked on another server instance. So, we want the status to remain in-process,
	// otherwise the handler on the other instance would not publish the VC because it would think that is has
	// already been processed.
	logger.Debug("Publishing anchor", logfields.WithAnchorURIString(anchorID),
		logfields.WithVerifiableCredentialID(vc.ID))

	vcBytes, err := canonicalizer.MarshalCanonical(vc)
	if err != nil {
		return fmt.Errorf("create new object with document: %w", err)
	}

	vcDataURI, err := datauri.New(vcBytes, h.dataURIMediaType)
	if err != nil {
		return fmt.Errorf("create data URI from VC: %w", err)
	}

	// Create a new anchor with the updated verifiable credential.
	anchorLink = linkset.NewLink(
		anchorLink.Anchor(), anchorLink.Author(), anchorLink.Profile(),
		anchorLink.Original(), anchorLink.Related(),
		linkset.NewReference(vcDataURI, linkset.TypeJSONLD),
	)

	err = h.publisher.Publish(ctx, linkset.New(anchorLink))
	if err != nil {
		return fmt.Errorf("publish credential[%s]: %w", anchorID, err)
	}

	logger.Info("Setting anchor status to completed", logfields.WithAnchorURIString(anchorID),
		logfields.WithVerifiableCredentialID(vc.ID))

	err = h.StatusStore.AddStatus(anchorID, proofapi.AnchorIndexStatusCompleted)
	if err != nil {
		return fmt.Errorf("failed to change status to 'completed' for anchor [%s], VC [%s]: %w",
			anchorID, vc.ID, err)
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

			if !proofExists(vc.Proofs, witnessProof.Proof) {
				logger.Debug("Adding witness proof", logfields.WithProofDocument(witnessProof.Proof))

				vc.Context = addContextsFromProof(vc.Context, witnessProof)

				vc.Proofs = append(vc.Proofs, witnessProof.Proof)
			} else {
				logger.Debug("Not adding witness proof since it already exists", logfields.WithProofDocument(witnessProof.Proof))
			}
		}
	}

	return vc, nil
}

func proofExists(proofs []verifiable.Proof, proof verifiable.Proof) bool {
	for _, p := range proofs {
		if reflect.DeepEqual(p, proof) {
			return true
		}
	}

	return false
}

func addContextsFromProof(contexts []string, witnessProof vct.Proof) []string {
	proofType := witnessProof.Proof["type"]

	switch proofType {
	case vcsigner.Ed25519Signature2020:
		contexts = add(contexts, vcsigner.CtxEd25519Signature2020)
	case vcsigner.Ed25519Signature2018:
		contexts = add(contexts, vcsigner.CtxEd25519Signature2018)
	case vcsigner.JSONWebSignature2020:
		contexts = add(contexts, vcsigner.CtxJWS)
	}

	return contexts
}

func add(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}

	return append(values, value)
}
