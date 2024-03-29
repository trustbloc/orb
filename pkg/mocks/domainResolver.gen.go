// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"
)

type DomainResolver struct {
	ResolveDomainForDIDStub        func(string) (string, error)
	resolveDomainForDIDMutex       sync.RWMutex
	resolveDomainForDIDArgsForCall []struct {
		arg1 string
	}
	resolveDomainForDIDReturns struct {
		result1 string
		result2 error
	}
	resolveDomainForDIDReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *DomainResolver) ResolveDomainForDID(arg1 string) (string, error) {
	fake.resolveDomainForDIDMutex.Lock()
	ret, specificReturn := fake.resolveDomainForDIDReturnsOnCall[len(fake.resolveDomainForDIDArgsForCall)]
	fake.resolveDomainForDIDArgsForCall = append(fake.resolveDomainForDIDArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.ResolveDomainForDIDStub
	fakeReturns := fake.resolveDomainForDIDReturns
	fake.recordInvocation("ResolveDomainForDID", []interface{}{arg1})
	fake.resolveDomainForDIDMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *DomainResolver) ResolveDomainForDIDCallCount() int {
	fake.resolveDomainForDIDMutex.RLock()
	defer fake.resolveDomainForDIDMutex.RUnlock()
	return len(fake.resolveDomainForDIDArgsForCall)
}

func (fake *DomainResolver) ResolveDomainForDIDCalls(stub func(string) (string, error)) {
	fake.resolveDomainForDIDMutex.Lock()
	defer fake.resolveDomainForDIDMutex.Unlock()
	fake.ResolveDomainForDIDStub = stub
}

func (fake *DomainResolver) ResolveDomainForDIDArgsForCall(i int) string {
	fake.resolveDomainForDIDMutex.RLock()
	defer fake.resolveDomainForDIDMutex.RUnlock()
	argsForCall := fake.resolveDomainForDIDArgsForCall[i]
	return argsForCall.arg1
}

func (fake *DomainResolver) ResolveDomainForDIDReturns(result1 string, result2 error) {
	fake.resolveDomainForDIDMutex.Lock()
	defer fake.resolveDomainForDIDMutex.Unlock()
	fake.ResolveDomainForDIDStub = nil
	fake.resolveDomainForDIDReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DomainResolver) ResolveDomainForDIDReturnsOnCall(i int, result1 string, result2 error) {
	fake.resolveDomainForDIDMutex.Lock()
	defer fake.resolveDomainForDIDMutex.Unlock()
	fake.ResolveDomainForDIDStub = nil
	if fake.resolveDomainForDIDReturnsOnCall == nil {
		fake.resolveDomainForDIDReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.resolveDomainForDIDReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DomainResolver) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.resolveDomainForDIDMutex.RLock()
	defer fake.resolveDomainForDIDMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *DomainResolver) recordInvocation(key string, args []interface{}) {
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
