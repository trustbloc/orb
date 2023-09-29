// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
)

type OperationStore struct {
	GetStub        func(string) ([]*operation.AnchoredOperation, error)
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		arg1 string
	}
	getReturns struct {
		result1 []*operation.AnchoredOperation
		result2 error
	}
	getReturnsOnCall map[int]struct {
		result1 []*operation.AnchoredOperation
		result2 error
	}
	PutStub        func([]*operation.AnchoredOperation) error
	putMutex       sync.RWMutex
	putArgsForCall []struct {
		arg1 []*operation.AnchoredOperation
	}
	putReturns struct {
		result1 error
	}
	putReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *OperationStore) Get(arg1 string) ([]*operation.AnchoredOperation, error) {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Get", []interface{}{arg1})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *OperationStore) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *OperationStore) GetCalls(stub func(string) ([]*operation.AnchoredOperation, error)) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = stub
}

func (fake *OperationStore) GetArgsForCall(i int) string {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	argsForCall := fake.getArgsForCall[i]
	return argsForCall.arg1
}

func (fake *OperationStore) GetReturns(result1 []*operation.AnchoredOperation, result2 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 []*operation.AnchoredOperation
		result2 error
	}{result1, result2}
}

func (fake *OperationStore) GetReturnsOnCall(i int, result1 []*operation.AnchoredOperation, result2 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 []*operation.AnchoredOperation
			result2 error
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 []*operation.AnchoredOperation
		result2 error
	}{result1, result2}
}

func (fake *OperationStore) Put(arg1 []*operation.AnchoredOperation) error {
	var arg1Copy []*operation.AnchoredOperation
	if arg1 != nil {
		arg1Copy = make([]*operation.AnchoredOperation, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.putMutex.Lock()
	ret, specificReturn := fake.putReturnsOnCall[len(fake.putArgsForCall)]
	fake.putArgsForCall = append(fake.putArgsForCall, struct {
		arg1 []*operation.AnchoredOperation
	}{arg1Copy})
	fake.recordInvocation("Put", []interface{}{arg1Copy})
	fake.putMutex.Unlock()
	if fake.PutStub != nil {
		return fake.PutStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.putReturns
	return fakeReturns.result1
}

func (fake *OperationStore) PutCallCount() int {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	return len(fake.putArgsForCall)
}

func (fake *OperationStore) PutCalls(stub func([]*operation.AnchoredOperation) error) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = stub
}

func (fake *OperationStore) PutArgsForCall(i int) []*operation.AnchoredOperation {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	argsForCall := fake.putArgsForCall[i]
	return argsForCall.arg1
}

func (fake *OperationStore) PutReturns(result1 error) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = nil
	fake.putReturns = struct {
		result1 error
	}{result1}
}

func (fake *OperationStore) PutReturnsOnCall(i int, result1 error) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = nil
	if fake.putReturnsOnCall == nil {
		fake.putReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.putReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *OperationStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *OperationStore) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ common.OperationStore = new(OperationStore)
