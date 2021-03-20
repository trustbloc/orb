/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

var logger = log.New("orb-txn-processor")

// OperationStore interface to access operation store.
type OperationStore interface {
	Put(ops []*operation.AnchoredOperation) error
	Get(suffix string) ([]*operation.AnchoredOperation, error)
}

// AnchorGraph interface to access anchors.
type AnchorGraph interface {
	GetDidAnchors(cid, did string) ([]string, error)
}

// Providers contains the providers required by the TxnProcessor.
type Providers struct {
	OpStore                   OperationStore
	OperationProtocolProvider protocol.OperationProvider
	AnchorGraph               AnchorGraph
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store.
type TxnProcessor struct {
	*Providers
}

// New returns a new document operation processor.
func New(providers *Providers) *TxnProcessor {
	return &TxnProcessor{
		Providers: providers,
	}
}

// Process persists all of the operations for the given anchor.
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return fmt.Errorf("failed to retrieve operations for anchor string[%s]: %s", sidetreeTxn.AnchorString, err)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func (p *TxnProcessor) processTxnOperations(txnOps []*operation.AnchoredOperation, sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing %d transaction operations", len(txnOps))

	batchSuffixes := make(map[string]bool)

	var ops []*operation.AnchoredOperation

	for _, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in transaction operations: discarding operation %v", sidetreeTxn.Namespace, op.UniqueSuffix, op) //nolint:lll

			continue
		}

		opsSoFar, err := p.OpStore.Get(op.UniqueSuffix)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			return err
		}

		// Get all references for this did from anchor graph starting from Sidetree txn reference
		didRefs, err := p.AnchorGraph.GetDidAnchors(sidetreeTxn.Reference, op.UniqueSuffix)
		if err != nil {
			return err
		}

		// check that number of operations in the store matches the number of anchors in the graph for that did
		if len(didRefs) != len(opsSoFar) {
			// TODO: This should not happen if we actively 'observe' batch writers
			// however if can happen if observer starts starts observing new system and it is not done in order
			// for now reject this case
			return fmt.Errorf("discrepancy between anchors in the graph[%d] and anchored operations[%d] for did: %s", len(didRefs), len(opsSoFar), op.UniqueSuffix) //nolint:lll
		}

		// TODO: Should we check that anchored operation reference matches anchored graph

		op.TransactionTime = sidetreeTxn.TransactionTime

		// The genesis time of the protocol that was used for this operation
		op.ProtocolGenesisTime = sidetreeTxn.ProtocolGenesisTime

		op.Reference = sidetreeTxn.Reference

		logger.Debugf("updated operation time: %s", op.UniqueSuffix)
		ops = append(ops, op)

		batchSuffixes[op.UniqueSuffix] = true
	}

	err := p.OpStore.Put(ops)
	if err != nil {
		return errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
	}

	return nil
}
