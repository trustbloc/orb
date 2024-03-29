// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

type ExpiryService struct {
	RegisterStub        func(storage.Store, string, string, ...expiry.Option)
	registerMutex       sync.RWMutex
	registerArgsForCall []struct {
		arg1 storage.Store
		arg2 string
		arg3 string
		arg4 []expiry.Option
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ExpiryService) Register(arg1 storage.Store, arg2 string, arg3 string, arg4 ...expiry.Option) {
	fake.registerMutex.Lock()
	fake.registerArgsForCall = append(fake.registerArgsForCall, struct {
		arg1 storage.Store
		arg2 string
		arg3 string
		arg4 []expiry.Option
	}{arg1, arg2, arg3, arg4})
	stub := fake.RegisterStub
	fake.recordInvocation("Register", []interface{}{arg1, arg2, arg3, arg4})
	fake.registerMutex.Unlock()
	if stub != nil {
		fake.RegisterStub(arg1, arg2, arg3, arg4...)
	}
}

func (fake *ExpiryService) RegisterCallCount() int {
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	return len(fake.registerArgsForCall)
}

func (fake *ExpiryService) RegisterCalls(stub func(storage.Store, string, string, ...expiry.Option)) {
	fake.registerMutex.Lock()
	defer fake.registerMutex.Unlock()
	fake.RegisterStub = stub
}

func (fake *ExpiryService) RegisterArgsForCall(i int) (storage.Store, string, string, []expiry.Option) {
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	argsForCall := fake.registerArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4
}

func (fake *ExpiryService) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.registerMutex.RLock()
	defer fake.registerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ExpiryService) recordInvocation(key string, args []interface{}) {
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
