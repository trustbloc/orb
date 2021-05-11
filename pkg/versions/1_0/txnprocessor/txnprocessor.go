/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/context/common"
)

var logger = log.New("orb-txn-processor")

// Providers contains the providers required by the TxnProcessor.
type Providers struct {
	OpStore                   common.OperationStore
	OperationProtocolProvider protocol.OperationProvider
	AnchorGraph               common.AnchorGraph
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
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn, suffixes ...string) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return fmt.Errorf("failed to retrieve operations for anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	if len(suffixes) > 0 {
		txnOps = filterOps(txnOps, suffixes)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func filterOps(txnOps []*operation.AnchoredOperation, suffixes []string) []*operation.AnchoredOperation {
	var ops []*operation.AnchoredOperation

	for _, op := range txnOps {
		if contains(suffixes, op.UniqueSuffix) {
			ops = append(ops, op)
		}
	}

	return ops
}

func contains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
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
			return fmt.Errorf("failed to get all DID anchors: %w", err)
		}

		// check that number of operations in the store matches the number of anchors in the graph for that did
		if len(didRefs)-1 != len(opsSoFar) {
			// TODO: This should not happen if we actively 'observe' batch writers
			// however if can happen if observer starts starts observing new system and it is not done in order
			// for now reject this case
			return fmt.Errorf("discrepancy between previous anchors in the graph[%d] and anchored operations[%d] for did: %s", len(didRefs)-1, len(opsSoFar), op.UniqueSuffix) //nolint:lll
		}

		// TODO: Should we check that anchored operation reference matches anchored graph

		op.TransactionTime = sidetreeTxn.TransactionTime

		// The genesis time of the protocol that was used for this operation
		op.ProtocolGenesisTime = sidetreeTxn.ProtocolGenesisTime

		webCASURLSplitBySlashes := strings.Split(sidetreeTxn.Reference, "/")

		cid := webCASURLSplitBySlashes[len(webCASURLSplitBySlashes)-1]

		op.Reference = cid

		logger.Debugf("updated operation time: %s", op.UniqueSuffix)
		ops = append(ops, op)

		batchSuffixes[op.UniqueSuffix] = true
	}

	if err := p.OpStore.Put(ops); err != nil {
		return fmt.Errorf("failed to store operation from anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	return nil
}
