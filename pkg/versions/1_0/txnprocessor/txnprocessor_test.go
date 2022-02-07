/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

const (
	anchorString = "1.coreIndexURI"
	canonicalRef = "ref"
	suffix       = "abc"
)

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		providers := &Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: &mockTxnOpsProvider{},
		}

		p := New(providers)
		_, err := p.Process(txn.SidetreeTxn{})
		require.NoError(t, err)
	})

	t.Run("success - suffix provided (for did discovery)", func(t *testing.T) {
		providers := &Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: &mockTxnOpsProvider{},
		}

		p := New(providers)
		_, err := p.Process(txn.SidetreeTxn{AnchorString: anchorString}, suffix)
		require.NoError(t, err)
	})

	t.Run("success - suffix provided not in batch (filtered)", func(t *testing.T) {
		providers := &Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: &mockTxnOpsProvider{},
		}

		p := New(providers)
		_, err := p.Process(txn.SidetreeTxn{AnchorString: anchorString}, "different")
		require.NoError(t, err)
	})

	t.Run("error - error from txn operations provider", func(t *testing.T) {
		errExpected := fmt.Errorf("txn operations provider error")

		opp := &mockTxnOpsProvider{
			err: errExpected,
		}

		providers := &Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: opp,
		}

		p := New(providers)
		_, err := p.Process(txn.SidetreeTxn{})
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
		}

		p := New(providers)
		_, err := p.processTxnOperations([]*operation.AnchoredOperation{{UniqueSuffix: "abc"}},
			&txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from anchor string")
	})

	t.Run("test error from operationStore Get", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore: &mockOperationStore{getFunc: func(suffix string) ([]*operation.AnchoredOperation, error) {
				return nil, fmt.Errorf("get error")
			}},
		}

		p := New(providers)
		_, err := p.processTxnOperations([]*operation.AnchoredOperation{{UniqueSuffix: suffix}},
			&txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("success - new operation added", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		p := New(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		_, err = p.processTxnOperations(batchOps, &txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})

	t.Run("success - operation already processed", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore: &mockOperationStore{getFunc: func(suffix string) ([]*operation.AnchoredOperation, error) {
				return []*operation.AnchoredOperation{
					{UniqueSuffix: suffix, CanonicalReference: canonicalRef},
				}, nil
			}},
		}

		p := New(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(
			&txn.SidetreeTxn{
				AnchorString:       anchorString,
				CanonicalReference: canonicalRef,
			})
		require.NoError(t, err)

		_, err = p.processTxnOperations(batchOps,
			&txn.SidetreeTxn{AnchorString: anchorString, CanonicalReference: canonicalRef})
		require.NoError(t, err)
	})

	t.Run("success - multiple operations with same suffix in transaction operations", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		p := New(providers)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		// add same operations again to create scenario where batch has multiple operations with same suffix
		// only first operation will be processed, subsequent operations will be discarded
		batchOps = append(batchOps, batchOps...)

		_, err = p.processTxnOperations(batchOps, &txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})

	t.Run("success - with unpublished operation store option", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		opt := WithUnpublishedOperationStore(&mockUnpublishedOpsStore{}, []operation.Type{operation.TypeUpdate})

		p := New(providers, opt)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		_, err = p.processTxnOperations(batchOps, &txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})

	t.Run("error - unpublished operation store error", func(t *testing.T) {
		providers := &Providers{
			OperationProtocolProvider: &mockTxnOpsProvider{},
			OpStore:                   &mockOperationStore{},
		}

		opt := WithUnpublishedOperationStore(
			&mockUnpublishedOpsStore{DeleteAllErr: fmt.Errorf("delete all error")},
			[]operation.Type{operation.TypeUpdate})

		p := New(providers, opt)
		batchOps, err := p.OperationProtocolProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		_, err = p.processTxnOperations(batchOps, &txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to delete unpublished operations for anchor string[1.coreIndexURI]: delete all error")
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
		UniqueSuffix:       suffix,
		CanonicalReference: canonicalRef,
		Type:               operation.TypeUpdate,
	}

	return []*operation.AnchoredOperation{op}, nil
}

type mockUnpublishedOpsStore struct {
	DeleteAllErr error
}

func (m *mockUnpublishedOpsStore) DeleteAll(_ []*operation.AnchoredOperation) error {
	return m.DeleteAllErr
}
