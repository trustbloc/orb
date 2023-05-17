/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inspector

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

var logger = log.New("policy-inspector")

// Inspector re-evaluates currently selected witnesses.
type Inspector struct {
	*Providers

	maxWitnessDelay time.Duration
	tracer          trace.Tracer
}

type anchorLinkStore interface {
	Get(id string) (*linkset.Link, error)
}

// Providers contains the providers required by the client.
type Providers struct {
	AnchorLinkStore anchorLinkStore
	Outbox          outboxProvider
	WitnessStore    witnessStore
	WitnessPolicy   witnessPolicy
}

type witnessStore interface {
	Get(anchorID string) ([]*proof.WitnessProof, error)
	UpdateWitnessSelection(anchorID string, witnesses []*url.URL, selected bool) error
}

type witnessPolicy interface {
	Select(witnesses []*proof.Witness, excluded ...*proof.Witness) ([]*proof.Witness, error)
}

// Outbox defines outbox.
type Outbox interface {
	Post(ctx context.Context, activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

type outboxProvider func() Outbox

// New returns a new anchor inspector.
func New(providers *Providers, maxWitnessDelay time.Duration) (*Inspector, error) {
	w := &Inspector{
		Providers:       providers,
		maxWitnessDelay: maxWitnessDelay,
		tracer:          tracing.Tracer(tracing.SubsystemAnchor),
	}

	return w, nil
}

// CheckPolicy will look into which witness did not provide proof and reselect different set of witnesses.
func (c *Inspector) CheckPolicy(anchorID string) error {
	anchorLink, err := c.AnchorLinkStore.Get(anchorID)
	if err != nil {
		return fmt.Errorf("get anchor event: %w", err)
	}

	witnessesIRI, err := c.getAdditionalWitnesses(anchorLink.Anchor().String())
	if err != nil {
		return fmt.Errorf("failed to get additional witnesses: %w", err)
	}

	witnessesIRI = append(witnessesIRI, vocab.PublicIRI)

	ctx, span := c.tracer.Start(context.Background(), "inspect witness policy")
	defer span.End()

	// send an offer activity to additional witnesses
	err = c.postOfferActivity(ctx, anchorLink, witnessesIRI)
	if err != nil {
		return fmt.Errorf("failed to post new offer activity to additional witnesses for anchor %s: %w",
			anchorLink.Anchor(), err)
	}

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Inspector) postOfferActivity(ctx context.Context, anchorLink *linkset.Link, witnessesIRI []*url.URL) error {
	logger.Debug("Sending anchor to additional witnesses",
		logfields.WithAnchorURI(anchorLink.Anchor()), logfields.WithWitnessURIs(witnessesIRI...))

	anchorLinksetDoc, err := vocab.MarshalToDoc(linkset.New(anchorLink))
	if err != nil {
		return fmt.Errorf("marshal anchor linkset: %w", err)
	}

	startTime := time.Now()
	endTime := startTime.Add(c.maxWitnessDelay)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(
			vocab.WithDocument(anchorLinksetDoc),
		),
		vocab.WithTo(witnessesIRI...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
	)

	activityID, err := c.Outbox().Post(ctx, offer)
	if err != nil {
		return fmt.Errorf("failed to post additional offer for anchor[%s]: %w", anchorLink.Anchor(), err)
	}

	logger.Info("Posted 'Offer' activity to additional witnesses", logfields.WithAnchorURI(anchorLink.Anchor()),
		logfields.WithActivityID(activityID), logfields.WithWitnessURIs(witnessesIRI...))

	return nil
}

func (c *Inspector) getAdditionalWitnesses(anchorID string) ([]*url.URL, error) {
	witnesses, err := c.WitnessStore.Get(anchorID)
	if err != nil {
		return nil, fmt.Errorf("failed to get witnesses for anchorID[%s]: %w", anchorID, err)
	}

	var allWitnesses []*proof.Witness

	var excludeWitnesses []*proof.Witness

	var selectedWitnessesIRI []*url.URL

	// exclude failed witnesses from the witness selection list
	for _, w := range witnesses {
		if w.Selected {
			selectedWitnessesIRI = append(selectedWitnessesIRI, w.URI.URL())

			if w.Proof == nil {
				// something went wrong with this selected witness - no proof provided
				logger.Info("Witness did not return proof for anchor within the 'in-process' grace period. "+
					"This witness will be ignored during re-selection of witnesses.",
					logfields.WithWitnessURI(w.URI), logfields.WithAnchorURIString(anchorID))

				excludeWitness := &proof.Witness{
					Type:     w.Type,
					URI:      w.URI,
					HasLog:   w.HasLog,
					Selected: w.Selected,
				}

				excludeWitnesses = append(excludeWitnesses, excludeWitness)
			}
		}

		witness := &proof.Witness{
			Type:     w.Type,
			URI:      w.URI,
			HasLog:   w.HasLog,
			Selected: w.Selected,
		}

		allWitnesses = append(allWitnesses, witness)
	}

	newlySelectedWitnesses, err := c.WitnessPolicy.Select(allWitnesses, excludeWitnesses...)
	if err != nil {
		return nil, fmt.Errorf("select witnesses for anchorID[%s]: %w", anchorID, err)
	}

	newlySelectedWitnessesIRI, _ := getUniqueWitnesses(newlySelectedWitnesses)

	additionalWitnessesIRI := difference(newlySelectedWitnessesIRI, selectedWitnessesIRI)

	if len(additionalWitnessesIRI) == 0 {
		return nil, fmt.Errorf("unable to select additional witnesses for anchorID[%s] from newly selected "+
			"witnesses[%s] and previously selected witnesses[%s] with exclude witnesses[%s]: %w",
			anchorID, newlySelectedWitnessesIRI, selectedWitnessesIRI, excludeWitnesses, orberrors.ErrWitnessesNotFound)
	}

	// update selected flag for additional witnesses
	err = c.WitnessStore.UpdateWitnessSelection(anchorID, additionalWitnessesIRI, true)
	if err != nil {
		return nil, fmt.Errorf("update witness selection flag for anchorID[%s]: %w", anchorID, err)
	}

	logger.Debug("Selected witnesses for anchor", logfields.WithTotal(len(newlySelectedWitnessesIRI)),
		logfields.WithAnchorURIString(anchorID), logfields.WithWitnessURIs(newlySelectedWitnessesIRI...))

	return additionalWitnessesIRI, nil
}

func getUniqueWitnesses(witnesses []*proof.Witness) ([]*url.URL, map[string]bool) {
	uniqueWitnesses := make(map[string]bool)

	var witnessesIRI []*url.URL

	for _, w := range witnesses {
		_, ok := uniqueWitnesses[w.URI.String()]
		if !ok {
			witnessesIRI = append(witnessesIRI, w.URI.URL())
			uniqueWitnesses[w.URI.String()] = true
		}
	}

	return witnessesIRI, uniqueWitnesses
}

func difference(a, b []*url.URL) []*url.URL {
	var result []*url.URL

	hash := make(map[string]bool)
	for _, e := range b {
		hash[e.String()] = true
	}

	for _, e := range a {
		if _, ok := hash[e.String()]; !ok {
			result = append(result, e)
		}
	}

	return result
}
