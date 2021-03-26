/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import "sync"

// BDDContext
type BDDContext struct {
	composition *Composition
	mutex       sync.RWMutex
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *BDDContext) BeforeScenario(interface{}) {
}

// AfterScenario execute code after bdd scenario
func (b *BDDContext) AfterScenario(interface{}, error) {
}

// SetComposition sets the Docker composition in the context
func (b *BDDContext) SetComposition(composition *Composition) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.composition != nil {
		panic("composition is already set")
	}

	b.composition = composition
}

// Composition returns the Docker composition
func (b *BDDContext) Composition() *Composition {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	return b.composition
}
