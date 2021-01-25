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

// Providers contains the providers required by the TxnProcessor.
type Providers struct {
	OpStore                   OperationStore
	OperationProtocolProvider protocol.OperationProvider
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

		//  TODO: Special logic here to walk everything in the graph for that did
		// check that number of operations in the store matches the number of cids when walking graph for that did
		// (may even have to check if operations are equal - step 2)
		// otherwise push cids + did (in reverse order) to observer for processing (this is brand new functionality)
		// before storing dids from this batch

		// For now just see how many ops we have so far and set that as operation index

		var txnTime uint64 // 0 is default for create operation

		opsSoFar, err := p.OpStore.Get(op.UniqueSuffix)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			return err
		}

		if err != nil {
			// unique suffix not found
			if op.Type != operation.TypeCreate {
				// start discovering graph for this did here
				// have to retrieve ops again after discovering
				logger.Warnf("non-create operation encountered for unique suffix that doesn't exist")
			}
		}

		txnTime = uint64(len(opsSoFar))

		op.TransactionTime = txnTime

		// The genesis time of the protocol that was used for this operation
		op.ProtocolGenesisTime = sidetreeTxn.ProtocolGenesisTime

		logger.Debugf("updated operation with blockchain time: %s", op.UniqueSuffix)
		ops = append(ops, op)

		batchSuffixes[op.UniqueSuffix] = true
	}

	err := p.OpStore.Put(ops)
	if err != nil {
		return errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
	}

	return nil
}
