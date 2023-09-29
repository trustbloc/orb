/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"
	"strings"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	svcprotocol "github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-svc-go/pkg/api/txn"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/context/common"
)

var logger = log.New("orb-txn-processor")

// Providers contains the providers required by the TxnProcessor.
type Providers struct {
	OpStore                   common.OperationStore
	OperationProtocolProvider svcprotocol.OperationProvider
}

type unpublishedOperationStore interface {
	// DeleteAll deletes unpublished operation for provided suffixes.
	DeleteAll(ops []*operation.AnchoredOperation) error
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store.
type TxnProcessor struct {
	*Providers

	unpublishedOperationStore unpublishedOperationStore
	unpublishedOperationTypes []operation.Type
}

// New returns a new document operation processor.
func New(providers *Providers, opts ...Option) *TxnProcessor {
	tp := &TxnProcessor{
		Providers: providers,

		unpublishedOperationStore: &noopUnpublishedOpsStore{},
		unpublishedOperationTypes: []operation.Type{},
	}

	// apply options
	for _, opt := range opts {
		opt(tp)
	}

	return tp
}

// Option is an option for transaction processor.
type Option func(opts *TxnProcessor)

// WithUnpublishedOperationStore is unpublished operation store option.
func WithUnpublishedOperationStore(store unpublishedOperationStore, opTypes []operation.Type) Option {
	return func(opts *TxnProcessor) {
		opts.unpublishedOperationStore = store
		opts.unpublishedOperationTypes = opTypes
	}
}

// Process persists the operations for the given anchor.
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn, suffixes ...string) (int, error) { //nolint:gocritic
	logger.Debug("Processing sidetree txn", logfields.WithSidetreeTxn(sidetreeTxn))

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve operations for anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	if len(suffixes) > 0 {
		txnOps = filterOps(txnOps, suffixes)
	}

	return p.processTxnOperations(txnOps, &sidetreeTxn)
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

func (p *TxnProcessor) processTxnOperations(txnOps []*operation.AnchoredOperation, sidetreeTxn *txn.SidetreeTxn) (int, error) {
	logger.Debug("Processing transaction operations", logfields.WithTotal(len(txnOps)))

	batchSuffixes := make(map[string]bool)

	var unpublishedOps []*operation.AnchoredOperation

	var ops []*operation.AnchoredOperation

	for _, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warn("Duplicate suffix found in transaction operations. Discarding operation.",
				logfields.WithNamespace(sidetreeTxn.Namespace), logfields.WithSuffix(op.UniqueSuffix),
				logfields.WithOperation(op))

			continue
		}

		opsSoFar, err := p.OpStore.Get(op.UniqueSuffix)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			return 0, err
		}

		if containsCanonicalReference(opsSoFar, sidetreeTxn.CanonicalReference) {
			logger.Debug("Ignoring operation that has already been inserted",
				logfields.WithNamespace(sidetreeTxn.Namespace), logfields.WithCanonicalRef(sidetreeTxn.CanonicalReference))

			// this operation has already been inserted - ignore it
			continue
		}

		op.TransactionTime = sidetreeTxn.TransactionTime
		op.ProtocolVersion = sidetreeTxn.ProtocolVersion
		op.CanonicalReference = sidetreeTxn.CanonicalReference
		op.EquivalentReferences = sidetreeTxn.EquivalentReferences

		logger.Debug("Updated operation time", logfields.WithSuffix(op.UniqueSuffix))
		ops = append(ops, op)

		batchSuffixes[op.UniqueSuffix] = true

		if containsOperationType(p.unpublishedOperationTypes, op.Type) {
			logger.Debug("Added operation for deletion from unpublished operation store",
				logfields.WithSuffix(op.UniqueSuffix))

			unpublishedOps = append(unpublishedOps, op)
		}
	}

	if len(ops) == 0 {
		logger.Info("No operations to be processed for anchor string",
			logfields.WithAnchorString(sidetreeTxn.AnchorString))

		return 0, nil
	}

	if err := p.OpStore.Put(ops); err != nil {
		return 0, fmt.Errorf("failed to store operation from anchor string[%s]: %w",
			sidetreeTxn.AnchorString, err)
	}

	err := p.unpublishedOperationStore.DeleteAll(unpublishedOps)
	if err != nil {
		return 0, fmt.Errorf("failed to delete unpublished operations for anchor string[%s]: %w",
			sidetreeTxn.AnchorString, err)
	}

	return len(ops), nil
}

func containsCanonicalReference(ops []*operation.AnchoredOperation, ref string) bool {
	for _, op := range ops {
		if op.CanonicalReference == ref {
			return true
		}
	}

	return false
}

func containsOperationType(values []operation.Type, value operation.Type) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

type noopUnpublishedOpsStore struct{}

func (noop *noopUnpublishedOpsStore) DeleteAll(_ []*operation.AnchoredOperation) error {
	return nil
}
