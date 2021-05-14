// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	ariesverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

type KeyResolver struct {
	ResolveStub        func(keyID string) (*ariesverifier.PublicKey, error)
	resolveMutex       sync.RWMutex
	resolveArgsForCall []struct {
		keyID string
	}
	resolveReturns struct {
		result1 *ariesverifier.PublicKey
		result2 error
	}
	resolveReturnsOnCall map[int]struct {
		result1 *ariesverifier.PublicKey
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *KeyResolver) Resolve(keyID string) (*ariesverifier.PublicKey, error) {
	fake.resolveMutex.Lock()
	ret, specificReturn := fake.resolveReturnsOnCall[len(fake.resolveArgsForCall)]
	fake.resolveArgsForCall = append(fake.resolveArgsForCall, struct {
		keyID string
	}{keyID})
	fake.recordInvocation("Resolve", []interface{}{keyID})
	fake.resolveMutex.Unlock()
	if fake.ResolveStub != nil {
		return fake.ResolveStub(keyID)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.resolveReturns.result1, fake.resolveReturns.result2
}

func (fake *KeyResolver) ResolveCallCount() int {
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	return len(fake.resolveArgsForCall)
}

func (fake *KeyResolver) ResolveArgsForCall(i int) string {
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	return fake.resolveArgsForCall[i].keyID
}

func (fake *KeyResolver) ResolveReturns(result1 *ariesverifier.PublicKey, result2 error) {
	fake.ResolveStub = nil
	fake.resolveReturns = struct {
		result1 *ariesverifier.PublicKey
		result2 error
	}{result1, result2}
}

func (fake *KeyResolver) ResolveReturnsOnCall(i int, result1 *ariesverifier.PublicKey, result2 error) {
	fake.ResolveStub = nil
	if fake.resolveReturnsOnCall == nil {
		fake.resolveReturnsOnCall = make(map[int]struct {
			result1 *ariesverifier.PublicKey
			result2 error
		})
	}
	fake.resolveReturnsOnCall[i] = struct {
		result1 *ariesverifier.PublicKey
		result2 error
	}{result1, result2}
}

func (fake *KeyResolver) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.resolveMutex.RLock()
	defer fake.resolveMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *KeyResolver) recordInvocation(key string, args []interface{}) {
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