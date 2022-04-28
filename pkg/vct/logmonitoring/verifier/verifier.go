/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"github.com/google/trillian/merkle/logverifier"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/trustbloc/vct/pkg/controller/command"
)

// LogVerifier wraps Trillian functionality for verifying consistency proof and getting root hash from entries.
type LogVerifier struct{}

// New returns new client for monitoring VCT log consistency.
func New() *LogVerifier {
	return &LogVerifier{}
}

// GetRootHashFromEntries constructs Merkle tree from entries and calculates root hash.
func (v *LogVerifier) GetRootHashFromEntries(entries []*command.LeafEntry) ([]byte, error) {
	hasher := rfc6962.DefaultHasher
	fact := compact.RangeFactory{Hash: hasher.HashChildren}
	cr := fact.NewEmptyRange(0)

	// We don't simply iterate the map, as we need to preserve the leaves order.
	for _, entry := range entries {
		err := cr.Append(hasher.HashLeaf(entry.LeafInput), nil)
		if err != nil {
			return nil, err
		}
	}

	return cr.GetRootHash(nil)
}

// VerifyConsistencyProof verifies consistency proof.
func (v *LogVerifier) VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
	logVerifier := logverifier.New(rfc6962.DefaultHasher)

	return logVerifier.VerifyConsistencyProof(snapshot1, snapshot2, root1, root2, proof)
}
