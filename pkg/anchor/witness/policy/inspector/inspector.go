/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inspector

import (
	"fmt"
	"net/url"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
)

var logger = log.New("policy-inspector")

// Inspector re-evaluates currently selected witnesses.
type Inspector struct {
	*Providers

	maxWitnessDelay time.Duration
}

type anchorEventStore interface {
	Get(id string) (*vocab.AnchorEventType, error)
}

// Providers contains all of the providers required by the client.
type Providers struct {
	AnchorEventStore anchorEventStore
	Outbox           outboxProvider
	WitnessStore     witnessStore
	WitnessPolicy    witnessPolicy
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
	Post(activity *vocab.ActivityType) (*url.URL, error)
}

type outboxProvider func() Outbox

// New returns a new anchor inspector.
func New(providers *Providers, maxWitnessDelay time.Duration) (*Inspector, error) {
	w := &Inspector{
		Providers:       providers,
		maxWitnessDelay: maxWitnessDelay,
	}

	return w, nil
}

// CheckPolicy will look into which witness did not provide proof and reselect different set of witnesses.
func (c *Inspector) CheckPolicy(anchorID string) error {
	anchorEvent, err := c.AnchorEventStore.Get(anchorID)
	if err != nil {
		return fmt.Errorf("get anchor event: %w", err)
	}

	witnessesIRI, err := c.getAdditionalWitnesses(anchorEvent.Index().String())
	if err != nil {
		return fmt.Errorf("failed to get additional witnesses: %w", err)
	}

	witnessesIRI = append(witnessesIRI, vocab.PublicIRI)

	// send an offer activity to additional witnesses
	err = c.postOfferActivity(anchorEvent, witnessesIRI)
	if err != nil {
		return fmt.Errorf("failed to post new offer activity to additional witnesses for anchor event %s: %w",
			anchorEvent.Index(), err)
	}

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Inspector) postOfferActivity(anchorEvent *vocab.AnchorEventType, witnessesIRI []*url.URL) error {
	logger.Debugf("sending anchor event[%s] to additional witnesses: %s", anchorEvent.Index(), witnessesIRI)

	startTime := time.Now()
	endTime := startTime.Add(c.maxWitnessDelay)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(anchorEvent),
		),
		vocab.WithTo(witnessesIRI...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
	)

	postID, err := c.Outbox().Post(offer)
	if err != nil {
		return fmt.Errorf("failed to post additional offer for anchor event[%s]: %w", anchorEvent.Index(), err)
	}

	logger.Debugf("created additional pre-announce activity for anchor event[%s], post id[%s]",
		anchorEvent.Index(), postID)

	return nil
}

func (c *Inspector) getAdditionalWitnesses(anchorID string) ([]*url.URL, error) { //nolint:funlen
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
			selectedWitnessesIRI = append(selectedWitnessesIRI, w.URI)

			if w.Proof == nil {
				// something went wrong with this selected witness - no proof provided
				logger.Debugf("witness[%s] did not return proof within 'in-process' grace period, "+
					"this witness will be ignored during re-selecting witnesses.", w.URI.String())

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
		return nil, fmt.Errorf("select witnesses: %w", err)
	}

	newlySelectedWitnessesIRI, _ := getUniqueWitnesses(newlySelectedWitnesses)

	additionalWitnessesIRI := difference(newlySelectedWitnessesIRI, selectedWitnessesIRI)

	if len(additionalWitnessesIRI) == 0 {
		return nil, fmt.Errorf("unable to select additional witnesses[%s] from newly selected witnesses[%s] "+
			"and previously selected witnesses[%s] with exclude witnesses[%s]",
			additionalWitnessesIRI, newlySelectedWitnessesIRI, selectedWitnessesIRI, excludeWitnesses)
	}

	// update selected flag for additional witnesses
	err = c.WitnessStore.UpdateWitnessSelection(anchorID, additionalWitnessesIRI, true)
	if err != nil {
		return nil, fmt.Errorf("update witness selection flag: %w", err)
	}

	logger.Debugf("selected %d witnesses: %+v", len(newlySelectedWitnessesIRI), newlySelectedWitnessesIRI)

	return additionalWitnessesIRI, nil
}

func getUniqueWitnesses(witnesses []*proof.Witness) ([]*url.URL, map[string]bool) {
	uniqueWitnesses := make(map[string]bool)

	var witnessesIRI []*url.URL

	for _, w := range witnesses {
		_, ok := uniqueWitnesses[w.URI.String()]
		if !ok {
			witnessesIRI = append(witnessesIRI, w.URI)
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
