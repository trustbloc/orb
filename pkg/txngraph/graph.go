/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txngraph

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	"github.com/trustbloc/orb/pkg/api/txn"
)

// Graph manages transaction graph.
type Graph struct {
	cas cas.Client
}

// New creates new graph manager.
func New(c cas.Client) *Graph {
	return &Graph{cas: c}
}

// Add adds orb transaction to the transaction graph.
// Returns cid that contains orb transaction information.
func (l *Graph) Add(info *txn.OrbTransaction) (string, error) {
	// TODO: do we need canonical?
	txnBytes, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	return l.cas.Write(txnBytes)
}

// Read reads orb transaction.
func (l *Graph) Read(cid string) (*txn.OrbTransaction, error) {
	nodeBytes, err := l.cas.Read(cid)
	if err != nil {
		return nil, err
	}

	var node txn.OrbTransaction

	err = json.Unmarshal(nodeBytes, &node)
	if err != nil {
		return nil, err
	}

	return &node, nil
}

// GetDidTransactions returns all orb transactions that are referencing DID starting from cid.
func (l *Graph) GetDidTransactions(cid, did string) ([]string, error) {
	var refs []string

	cur := cid
	ok := true

	for ok {
		node, err := l.Read(cur)
		if err != nil {
			return nil, err
		}

		cur, ok = node.Payload.PreviousDidTxn[did]
		if ok {
			refs = append(refs, cur)
		}
	}

	return refs, nil
}
