// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"
)

type AuthTokenMgr struct {
	IsAuthRequiredStub        func(endpoint, method string) (bool, error)
	isAuthRequiredMutex       sync.RWMutex
	isAuthRequiredArgsForCall []struct {
		endpoint string
		method   string
	}
	isAuthRequiredReturns struct {
		result1 bool
		result2 error
	}
	isAuthRequiredReturnsOnCall map[int]struct {
		result1 bool
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *AuthTokenMgr) IsAuthRequired(endpoint string, method string) (bool, error) {
	fake.isAuthRequiredMutex.Lock()
	ret, specificReturn := fake.isAuthRequiredReturnsOnCall[len(fake.isAuthRequiredArgsForCall)]
	fake.isAuthRequiredArgsForCall = append(fake.isAuthRequiredArgsForCall, struct {
		endpoint string
		method   string
	}{endpoint, method})
	fake.recordInvocation("IsAuthRequired", []interface{}{endpoint, method})
	fake.isAuthRequiredMutex.Unlock()
	if fake.IsAuthRequiredStub != nil {
		return fake.IsAuthRequiredStub(endpoint, method)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.isAuthRequiredReturns.result1, fake.isAuthRequiredReturns.result2
}

func (fake *AuthTokenMgr) IsAuthRequiredCallCount() int {
	fake.isAuthRequiredMutex.RLock()
	defer fake.isAuthRequiredMutex.RUnlock()
	return len(fake.isAuthRequiredArgsForCall)
}

func (fake *AuthTokenMgr) IsAuthRequiredArgsForCall(i int) (string, string) {
	fake.isAuthRequiredMutex.RLock()
	defer fake.isAuthRequiredMutex.RUnlock()
	return fake.isAuthRequiredArgsForCall[i].endpoint, fake.isAuthRequiredArgsForCall[i].method
}

func (fake *AuthTokenMgr) IsAuthRequiredReturns(result1 bool, result2 error) {
	fake.IsAuthRequiredStub = nil
	fake.isAuthRequiredReturns = struct {
		result1 bool
		result2 error
	}{result1, result2}
}

func (fake *AuthTokenMgr) IsAuthRequiredReturnsOnCall(i int, result1 bool, result2 error) {
	fake.IsAuthRequiredStub = nil
	if fake.isAuthRequiredReturnsOnCall == nil {
		fake.isAuthRequiredReturnsOnCall = make(map[int]struct {
			result1 bool
			result2 error
		})
	}
	fake.isAuthRequiredReturnsOnCall[i] = struct {
		result1 bool
		result2 error
	}{result1, result2}
}

func (fake *AuthTokenMgr) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.isAuthRequiredMutex.RLock()
	defer fake.isAuthRequiredMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *AuthTokenMgr) recordInvocation(key string, args []interface{}) {
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