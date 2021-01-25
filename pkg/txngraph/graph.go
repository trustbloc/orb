/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txngraph

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
)

// Graph manages transaction graph.
type Graph struct {
	cas cas.Client
}

// New creates new graph manager.
func New(c cas.Client) *Graph {
	return &Graph{cas: c}
}

// Add adds txn node.
// Returns cid for transaction info.
func (l *Graph) Add(info *Node) (string, error) {
	// TODO: do we need canonical?
	txnBytes, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	return l.cas.Write(txnBytes)
}

// Read reads txn node.
func (l *Graph) Read(cid string) (*Node, error) {
	nodeBytes, err := l.cas.Read(cid)
	if err != nil {
		return nil, err
	}

	var node Node

	err = json.Unmarshal(nodeBytes, &node)
	if err != nil {
		return nil, err
	}

	return &node, nil
}
