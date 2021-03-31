/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/anchor/graph"
)

// OperationStore interface to access operation store.
type OperationStore interface {
	Get(suffix string) ([]*operation.AnchoredOperation, error)
	Put(ops []*operation.AnchoredOperation) error
}

// AnchorGraph interface to access did anchors.
type AnchorGraph interface {
	GetDidAnchors(cid, suffix string) ([]graph.Anchor, error)
}
