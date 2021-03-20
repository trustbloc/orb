/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	"github.com/trustbloc/orb/pkg/anchor/util"
)

// Graph manages anchor graph.
type Graph struct {
	*Providers
}

// Providers for anchor graph.
type Providers struct {
	Cas       cas.Client
	Pkf       verifiable.PublicKeyFetcher
	DocLoader ld.DocumentLoader
}

// New creates new graph manager.
func New(providers *Providers) *Graph {
	return &Graph{
		Providers: providers,
	}
}

// Add adds an anchor to the anchor graph.
// Returns cid that contains anchor information.
func (g *Graph) Add(vc *verifiable.Credential) (string, error) { //nolint:interfacer
	// TODO: do we need canonical?
	anchorBytes, err := vc.MarshalJSON()
	if err != nil {
		return "", err
	}

	return g.Cas.Write(anchorBytes)
}

// Read reads anchor.
func (g *Graph) Read(cid string) (*verifiable.Credential, error) {
	nodeBytes, err := g.Cas.Read(cid)
	if err != nil {
		return nil, err
	}

	return verifiable.ParseCredential(nodeBytes,
		verifiable.WithPublicKeyFetcher(g.Pkf),
		verifiable.WithJSONLDDocumentLoader(g.DocLoader))
}

// GetDidAnchors returns all anchors that are referencing DID starting from cid.
func (g *Graph) GetDidAnchors(cid, did string) ([]string, error) {
	var refs []string

	cur := cid
	ok := true

	for ok {
		node, err := g.Read(cur)
		if err != nil {
			return nil, err
		}

		payload, err := util.GetAnchorSubject(node)
		if err != nil {
			return nil, err
		}

		previousAnchors := payload.PreviousAnchors

		cur, ok = previousAnchors[did]
		if ok {
			if cur == "" { // create
				return refs, nil
			}

			refs = append(refs, cur)
		}
	}

	return refs, nil
}
