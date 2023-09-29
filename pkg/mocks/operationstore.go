/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"errors"
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-svc-go/pkg/observer"
)

// MockOpStoreProvider is a mock operation store provider.
type MockOpStoreProvider struct {
	opStore observer.OperationStore
}

// NewMockOpStoreProvider returns a new mock operation store provider.
func NewMockOpStoreProvider(opStore observer.OperationStore) *MockOpStoreProvider {
	return &MockOpStoreProvider{opStore: opStore}
}

// ForNamespace returns a mock operation store for the given namespace.
func (m *MockOpStoreProvider) ForNamespace(string) (observer.OperationStore, error) {
	return m.opStore, nil
}

// MockOperationStore is a mock operation store.
type MockOperationStore struct {
	mutex      sync.RWMutex
	operations map[string][]*operation.AnchoredOperation
}

// NewMockOperationStore returns a new mock operation store.
func NewMockOperationStore() *MockOperationStore {
	return &MockOperationStore{operations: make(map[string][]*operation.AnchoredOperation)}
}

// Put stores the given operations.
func (m *MockOperationStore) Put(ops []*operation.AnchoredOperation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, op := range ops {
		fmt.Printf("Putting operation type[%s], suffix[%s], txtime[%d], txnum[%d], pg[%d], buffer: %s\n",
			op.Type, op.UniqueSuffix, op.TransactionTime, op.TransactionNumber, op.ProtocolVersion, string(op.OperationRequest))
		m.operations[op.UniqueSuffix] = append(m.operations[op.UniqueSuffix], op)
	}

	fmt.Printf("Have operations: %+v\n", m.operations)

	return nil
}

// Get retrieves the operations for the given suffix.
func (m *MockOperationStore) Get(suffix string) ([]*operation.AnchoredOperation, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	ops := m.operations[suffix]
	if len(ops) == 0 {
		return nil, errors.New("uniqueSuffix not found in the store")
	}

	return ops, nil
}
