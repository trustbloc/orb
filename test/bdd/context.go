/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"sync"

	"github.com/cucumber/messages-go/v10"
)

// BDDContext bdd context.
type BDDContext struct {
	composition *Composition
	mutex       sync.RWMutex
	createdDID  string
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *BDDContext) BeforeScenario(*messages.Pickle) {}

// AfterScenario execute code after bdd scenario
func (b *BDDContext) AfterScenario(*messages.Pickle, error) {}

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
