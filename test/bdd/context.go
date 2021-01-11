/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

// BDDContext
type BDDContext struct {
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{}
	return &instance, nil
}

// BeforeScenario execute code before bdd scenario
func (b *BDDContext) BeforeScenario(scenarioOrScenarioOutline interface{}) {

}

// AfterScenario execute code after bdd scenario
func (b *BDDContext) AfterScenario(interface{}, error) {
}
