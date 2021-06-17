/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/anchor/util"
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
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, error)
}

type casWriter interface {
	Write(content []byte) (string, string, error)
}

// Add adds an anchor to the anchor graph.
// Returns cid that contains anchor information.
func (g *Graph) Add(vc *verifiable.Credential) (string, string, error) { //nolint:interfacer
	anchorBytes, err := vc.MarshalJSON()
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal VC: %w", err)
	}

	canonicalBytes, err := canonicalizer.MarshalCanonical(anchorBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal canonical: %w", err)
	}

	cid, hint, err := g.CasWriter.Write(canonicalBytes)
	if err != nil {
		return "", "", errors.NewTransient(fmt.Errorf("failed to add anchor to graph: %w", err))
	}

	logger.Debugf("added anchor[%s]: %s", cid, string(canonicalBytes))

	return cid, hint, nil
}

// Read reads anchor.
func (g *Graph) Read(cid string) (*verifiable.Credential, error) {
	anchorBytes, err := g.CasResolver.Resolve(nil, cid, nil)
	if err != nil {
		return nil, err
	}

	logger.Debugf("read anchor[%s]: %s", cid, string(anchorBytes))

	return verifiable.ParseCredential(anchorBytes,
		verifiable.WithPublicKeyFetcher(g.Pkf),
		verifiable.WithJSONLDDocumentLoader(g.DocLoader))
}

// Anchor contains anchor info plus corresponding cid.
type Anchor struct {
	Info *verifiable.Credential
	CID  string
}

// GetDidAnchors returns all anchors that are referencing did suffix starting from cid.
func (g *Graph) GetDidAnchors(cid, suffix string) ([]Anchor, error) {
	var refs []Anchor

	logger.Debugf("getting did anchors for cid[%s], suffix[%s]", cid, suffix)

	cur := cid
	ok := true

	for ok {
		node, err := g.Read(cur)
		if err != nil {
			return nil, fmt.Errorf("failed to read anchor[%s] for did[%s] f: %w", cur, suffix, err)
		}

		refs = append(refs, Anchor{Info: node, CID: cur})

		payload, err := util.GetAnchorSubject(node)
		if err != nil {
			return nil, err
		}

		previousAnchors := payload.PreviousAnchors

		cur, ok = previousAnchors[suffix]
		if ok && cur == "" { // create
			break
		}
	}

	return reverseOrder(refs), nil
}

func reverseOrder(original []Anchor) []Anchor {
	var reversed []Anchor

	for i := len(original) - 1; i >= 0; i-- {
		reversed = append(reversed, original[i])
	}

	return reversed
}
