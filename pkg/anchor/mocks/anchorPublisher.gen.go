// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
)

type AnchorPublisher struct {
	PublishAnchorStub        func(anchor *anchorinfo.AnchorInfo) error
	publishAnchorMutex       sync.RWMutex
	publishAnchorArgsForCall []struct {
		anchor *anchorinfo.AnchorInfo
	}
	publishAnchorReturns struct {
		result1 error
	}
	publishAnchorReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *AnchorPublisher) PublishAnchor(anchor *anchorinfo.AnchorInfo) error {
	fake.publishAnchorMutex.Lock()
	ret, specificReturn := fake.publishAnchorReturnsOnCall[len(fake.publishAnchorArgsForCall)]
	fake.publishAnchorArgsForCall = append(fake.publishAnchorArgsForCall, struct {
		anchor *anchorinfo.AnchorInfo
	}{anchor})
	fake.recordInvocation("PublishAnchor", []interface{}{anchor})
	fake.publishAnchorMutex.Unlock()
	if fake.PublishAnchorStub != nil {
		return fake.PublishAnchorStub(anchor)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.publishAnchorReturns.result1
}

func (fake *AnchorPublisher) PublishAnchorCallCount() int {
	fake.publishAnchorMutex.RLock()
	defer fake.publishAnchorMutex.RUnlock()
	return len(fake.publishAnchorArgsForCall)
}

func (fake *AnchorPublisher) PublishAnchorArgsForCall(i int) *anchorinfo.AnchorInfo {
	fake.publishAnchorMutex.RLock()
	defer fake.publishAnchorMutex.RUnlock()
	return fake.publishAnchorArgsForCall[i].anchor
}

func (fake *AnchorPublisher) PublishAnchorReturns(result1 error) {
	fake.PublishAnchorStub = nil
	fake.publishAnchorReturns = struct {
		result1 error
	}{result1}
}

func (fake *AnchorPublisher) PublishAnchorReturnsOnCall(i int, result1 error) {
	fake.PublishAnchorStub = nil
	if fake.publishAnchorReturnsOnCall == nil {
		fake.publishAnchorReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.publishAnchorReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *AnchorPublisher) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.publishAnchorMutex.RLock()
	defer fake.publishAnchorMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *AnchorPublisher) recordInvocation(key string, args []interface{}) {
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
