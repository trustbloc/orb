/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	"github.com/trustbloc/orb/pkg/anchor/util"
)

// Graph manages transaction graph.
type Graph struct {
	cas cas.Client
	pkf verifiable.PublicKeyFetcher
}

// New creates new graph manager.
func New(c cas.Client, pkf verifiable.PublicKeyFetcher) *Graph {
	return &Graph{cas: c, pkf: pkf}
}

// Add adds orb transaction to the transaction graph.
// Returns cid that contains orb transaction information.
func (g *Graph) Add(vc *verifiable.Credential) (string, error) { //nolint:interfacer
	// TODO: do we need canonical?
	txnBytes, err := vc.MarshalJSON()
	if err != nil {
		return "", err
	}

	return g.cas.Write(txnBytes)
}

// Read reads orb transaction.
func (g *Graph) Read(cid string) (*verifiable.Credential, error) {
	nodeBytes, err := g.cas.Read(cid)
	if err != nil {
		return nil, err
	}

	return verifiable.ParseCredential(nodeBytes, verifiable.WithPublicKeyFetcher(g.pkf))
}

// GetDidTransactions returns all orb transactions that are referencing DID starting from cid.
func (g *Graph) GetDidTransactions(cid, did string) ([]string, error) {
	var refs []string

	cur := cid
	ok := true

	for ok {
		node, err := g.Read(cur)
		if err != nil {
			return nil, err
		}

		payload, err := util.GetTransactionPayload(node)
		if err != nil {
			return nil, err
		}

		previousTxns := payload.PreviousTransactions

		cur, ok = previousTxns[did]
		if ok {
			if cur == "" { // create
				return refs, nil
			}

			refs = append(refs, cur)
		}
	}

	return refs, nil
}
