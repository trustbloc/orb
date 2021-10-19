/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("anchor-graph")

// Graph manages anchor graph.
type Graph struct {
	*Providers
}

// Providers for anchor graph.
type Providers struct {
	CasWriter   casWriter
	CasResolver casResolver
	Pkf         verifiable.PublicKeyFetcher
	DocLoader   ld.DocumentLoader
}

// New creates new graph manager.
func New(providers *Providers) *Graph {
	return &Graph{
		Providers: providers,
	}
}

type casResolver interface {
	Resolve(webCASURL *url.URL, hl string, data []byte) ([]byte, string, error)
}

type casWriter interface {
	Write(content []byte) (string, error)
}

// Add adds an anchor to the anchor graph.
// Returns hl that contains anchor information.
func (g *Graph) Add(anchorEvent *vocab.AnchorEventType) (string, error) { //nolint:interfacer
	canonicalBytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	if err != nil {
		return "", fmt.Errorf("failed to marshal anchor event: %w", err)
	}

	hl, err := g.CasWriter.Write(canonicalBytes)
	if err != nil {
		return "", errors.NewTransient(fmt.Errorf("failed to add anchor to graph: %w", err))
	}

	logger.Debugf("added anchor event[%s]: %s", hl, string(canonicalBytes))

	return hl, nil
}

// Read reads anchor.
func (g *Graph) Read(hl string) (*vocab.AnchorEventType, error) {
	anchorEventBytes, _, err := g.CasResolver.Resolve(nil, hl, nil)
	if err != nil {
		return nil, err
	}

	logger.Debugf("read anchor event [%s]: %s", hl, string(anchorEventBytes))

	anchorEvent := &vocab.AnchorEventType{}

	err = json.Unmarshal(anchorEventBytes, anchorEvent)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor event: %w", err)
	}

	return anchorEvent, nil
}

// Anchor contains anchor info plus corresponding hl.
type Anchor struct {
	Info *vocab.AnchorEventType
	CID  string
}

// GetDidAnchors returns all anchors that are referencing did suffix starting from hl.
func (g *Graph) GetDidAnchors(hl, suffix string) ([]Anchor, error) {
	var refs []Anchor

	logger.Debugf("getting did anchors for hl[%s], suffix[%s]", hl, suffix)

	cur := hl
	ok := true

	for ok {
		anchorEvent, err := g.Read(cur)
		if err != nil {
			return nil, fmt.Errorf("failed to read anchor event[%s] for did[%s]: %w", cur, suffix, err)
		}

		refs = append(refs, Anchor{
			CID:  cur,
			Info: anchorEvent,
		})

		payload, err := anchorevent.GetPayloadFromAnchorEvent(anchorEvent)
		if err != nil {
			return nil, err
		}

		previousAnchors := payload.PreviousAnchors

		cur, ok = contains(suffix, previousAnchors)
		if ok && cur == "" { // create
			break
		}
	}

	return reverseOrder(refs), nil
}

func contains(suffix string, previousAnchors []*subject.SuffixAnchor) (string, bool) {
	for _, val := range previousAnchors {
		if val.Suffix == suffix {
			return val.Anchor, true
		}
	}

	return "", false
}

func reverseOrder(original []Anchor) []Anchor {
	var reversed []Anchor

	for i := len(original) - 1; i >= 0; i-- {
		reversed = append(reversed, original[i])
	}

	return reversed
}
