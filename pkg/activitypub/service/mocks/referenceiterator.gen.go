// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"net/url"
	"sync"

	"github.com/trustbloc/orb/pkg/activitypub/client"
)

type ReferenceIterator struct {
	NextStub        func() (*url.URL, error)
	nextMutex       sync.RWMutex
	nextArgsForCall []struct{}
	nextReturns     struct {
		result1 *url.URL
		result2 error
	}
	nextReturnsOnCall map[int]struct {
		result1 *url.URL
		result2 error
	}
	TotalItemsStub        func() int
	totalItemsMutex       sync.RWMutex
	totalItemsArgsForCall []struct{}
	totalItemsReturns     struct {
		result1 int
	}
	totalItemsReturnsOnCall map[int]struct {
		result1 int
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ReferenceIterator) Next() (*url.URL, error) {
	fake.nextMutex.Lock()
	ret, specificReturn := fake.nextReturnsOnCall[len(fake.nextArgsForCall)]
	fake.nextArgsForCall = append(fake.nextArgsForCall, struct{}{})
	fake.recordInvocation("Next", []interface{}{})
	fake.nextMutex.Unlock()
	if fake.NextStub != nil {
		return fake.NextStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.nextReturns.result1, fake.nextReturns.result2
}

func (fake *ReferenceIterator) NextCallCount() int {
	fake.nextMutex.RLock()
	defer fake.nextMutex.RUnlock()
	return len(fake.nextArgsForCall)
}

func (fake *ReferenceIterator) NextReturns(result1 *url.URL, result2 error) {
	fake.NextStub = nil
	fake.nextReturns = struct {
		result1 *url.URL
		result2 error
	}{result1, result2}
}

func (fake *ReferenceIterator) NextReturnsOnCall(i int, result1 *url.URL, result2 error) {
	fake.NextStub = nil
	if fake.nextReturnsOnCall == nil {
		fake.nextReturnsOnCall = make(map[int]struct {
			result1 *url.URL
			result2 error
		})
	}
	fake.nextReturnsOnCall[i] = struct {
		result1 *url.URL
		result2 error
	}{result1, result2}
}

func (fake *ReferenceIterator) TotalItems() int {
	fake.totalItemsMutex.Lock()
	ret, specificReturn := fake.totalItemsReturnsOnCall[len(fake.totalItemsArgsForCall)]
	fake.totalItemsArgsForCall = append(fake.totalItemsArgsForCall, struct{}{})
	fake.recordInvocation("TotalItems", []interface{}{})
	fake.totalItemsMutex.Unlock()
	if fake.TotalItemsStub != nil {
		return fake.TotalItemsStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.totalItemsReturns.result1
}

func (fake *ReferenceIterator) TotalItemsCallCount() int {
	fake.totalItemsMutex.RLock()
	defer fake.totalItemsMutex.RUnlock()
	return len(fake.totalItemsArgsForCall)
}

func (fake *ReferenceIterator) TotalItemsReturns(result1 int) {
	fake.TotalItemsStub = nil
	fake.totalItemsReturns = struct {
		result1 int
	}{result1}
}

func (fake *ReferenceIterator) TotalItemsReturnsOnCall(i int, result1 int) {
	fake.TotalItemsStub = nil
	if fake.totalItemsReturnsOnCall == nil {
		fake.totalItemsReturnsOnCall = make(map[int]struct {
			result1 int
		})
	}
	fake.totalItemsReturnsOnCall[i] = struct {
		result1 int
	}{result1}
}

func (fake *ReferenceIterator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.nextMutex.RLock()
	defer fake.nextMutex.RUnlock()
	fake.totalItemsMutex.RLock()
	defer fake.totalItemsMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ReferenceIterator) recordInvocation(key string, args []interface{}) {
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

var _ client.ReferenceIterator = new(ReferenceIterator)
