/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

const anchorString = "1.coreIndexURI"

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("test error from txn operations provider", func(t *testing.T) {
		errExpected := fmt.Errorf("txn operations provider error")

		opp := &mockTxnOpsProvider{
			err: errExpected,
		}

		providers := &Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: opp,
		}

		p := New(providers)
		err := p.Process(txn.SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestProcessTxnOperations(t *testing.T) {
	t.Run("test error from operationStore Put", func(t *testing.T) {
		providers := &Providers{
			OpStore: &mockOperationStore{putFunc: func(ops []*operation.AnchoredOperation) error {
				return fmt.Errorf("put error")
			}},
			TxnGraph: &mockTxnGraph{},
		}

		p := New(providers)
		err := p.processTxnOperations([]*operation.AnchoredOperation{{UniqueSuffix: "abc"}},
			txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from anchor string")
	})

	t.Run("error - error retrieving cid from transaction graph", func(t *testing.T) {
		providers := &Providers{
			OpStore: &mockOperationStore{putFunc: func(ops []*operation.AnchoredOperation) error {
				return fmt.Errorf("put error")
			}},
			TxnGraph: &mockTxnGraph{Err: errors.New("graph error")},
		}

		p := New(providers)
		err := p.processTxnOperations([]*operation.AnchoredOperation{{UniqueSuffix: "abc"}},
			txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "graph error")
	})

	t.Run("error - discrepancy between did transactions in the graph and operation store", func(t *testing.T) {
		providers := &Providers{
			OpStore: &mockOperationStore{putFunc: func(ops []*operation.AnchoredOperation) error {
				return fmt.Errorf("put error")
			}},
			TxnGraph: &mockTxnGraph{DidTxns: []string{"one", "two"}},
		}

		p := New(providers)
		err := p.processTxnOperations([]*operation.AnchoredOperation{{UniqueSuffix: "abc"}},
			txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"discrepancy between transactions in the graph[2] and anchored operations[0] for did: abc")
	})

	t.Run("test success", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
			TxnGraph:                  &mockTxnGraph{},
		}

		p := New(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		err = p.processTxnOperations(batchOps, txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})

	t.Run("success - multiple operations with same suffix in transaction operations", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
			TxnGraph:                  &mockTxnGraph{},
		}

		p := New(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		// add same operations again to create scenario where batch has multiple operations with same suffix
		// only first operation will be processed, subsequent operations will be discarded
		batchOps = append(batchOps, batchOps...)

		err = p.processTxnOperations(batchOps, txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})
}

type mockOperationStore struct {
	putFunc func(ops []*operation.AnchoredOperation) error
	getFunc func(suffix string) ([]*operation.AnchoredOperation, error)
}

func (m *mockOperationStore) Put(ops []*operation.AnchoredOperation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}

	return nil
}

func (m *mockOperationStore) Get(suffix string) ([]*operation.AnchoredOperation, error) {
	if m.getFunc != nil {
		return m.getFunc(suffix)
	}

	return nil, nil
}

type mockTxnOpsProvider struct {
	err error
}

func (m *mockTxnOpsProvider) GetTxnOperations(_ *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	if m.err != nil {
		return nil, m.err
	}

	op := &operation.AnchoredOperation{
		UniqueSuffix: "abc",
	}

	return []*operation.AnchoredOperation{op}, nil
}

type mockTxnGraph struct {
	DidTxns []string
	Err     error
}

func (m *mockTxnGraph) GetDidTransactions(cid, did string) ([]string, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.DidTxns, nil
}
