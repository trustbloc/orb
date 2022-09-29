/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
)

var logger = log.NewStructured("anchor-graph")

// Graph manages anchor graph.
type Graph struct {
	*Providers
}

type anchorLinksetBuilder interface {
	GetPayloadFromAnchorLink(anchorLink *linkset.Link) (*subject.Payload, error)
}

// Providers for anchor graph.
type Providers struct {
	CasWriter            casWriter
	CasResolver          casResolver
	DocLoader            ld.DocumentLoader
	AnchorLinksetBuilder anchorLinksetBuilder
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
func (g *Graph) Add(anchorLinkset *linkset.Linkset) (string, error) { //nolint:interfacer
	canonicalBytes, err := canonicalizer.MarshalCanonical(anchorLinkset)
	if err != nil {
		return "", fmt.Errorf("failed to marshal anchor: %w", err)
	}

	hl, err := g.CasWriter.Write(canonicalBytes)
	if err != nil {
		return "", errors.NewTransient(fmt.Errorf("failed to add anchor to graph: %w", err))
	}

	logger.Debug("Added anchor", log.WithHashlink(hl), log.WithData(canonicalBytes))

	return hl, nil
}

// Read reads anchor.
func (g *Graph) Read(hl string) (*linkset.Linkset, error) {
	anchorLinksetBytes, _, err := g.CasResolver.Resolve(nil, hl, nil)
	if err != nil {
		return nil, err
	}

	logger.Debug("Read anchor Linkset", log.WithHashlink(hl), log.WithData(anchorLinksetBytes))

	anchorLinkset := &linkset.Linkset{}

	err = json.Unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor Linkset: %w", err)
	}

	return anchorLinkset, nil
}

// Anchor contains anchor info plus corresponding hl.
type Anchor struct {
	Info *linkset.Link
	CID  string
}

// GetDidAnchors returns all anchors that are referencing did suffix starting from hl.
func (g *Graph) GetDidAnchors(hl, suffix string) ([]Anchor, error) {
	var refs []Anchor

	cur := hl
	ok := true

	for ok {
		logger.Debug("Getting DID anchors", log.WithHashlink(cur), log.WithSuffix(suffix))

		anchorLinkset, err := g.Read(cur)
		if err != nil {
			return nil, fmt.Errorf("failed to read anchor[%s] for did[%s]: %w", cur, suffix, err)
		}

		anchorLink := anchorLinkset.Link()
		if anchorLink == nil {
			return nil, fmt.Errorf("empty anchor Linkset [%s]", cur)
		}

		refs = append(refs, Anchor{
			CID:  cur,
			Info: anchorLink,
		})

		payload, err := g.AnchorLinksetBuilder.GetPayloadFromAnchorLink(anchorLink)
		if err != nil {
			return nil, fmt.Errorf("get payload from anchor link: %w", err)
		}

		cur, ok = contains(suffix, payload.PreviousAnchors)
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
