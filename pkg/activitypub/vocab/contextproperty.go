/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
)

// ContextProperty holds one or more contexts.
type ContextProperty struct {
	contexts []Context
}

// NewContextProperty returns a new 'context' property. Nil is returned if no context was provided.
func NewContextProperty(context ...Context) *ContextProperty {
	if len(context) == 0 {
		return nil
	}

	return &ContextProperty{contexts: context}
}

// Contexts returns all of the contexts defined in the property.
func (p *ContextProperty) Contexts() []Context {
	if p == nil {
		return nil
	}

	return p.contexts
}

// Contains returns true if the property contains all of the given contexts.
func (p *ContextProperty) Contains(contexts ...Context) bool {
	if p == nil || len(contexts) == 0 {
		return false
	}

	for _, t := range contexts {
		if !p.contains(t) {
			return false
		}
	}

	return true
}

// ContainsAny returns true if the property contains any of the given contexts.
func (p *ContextProperty) ContainsAny(contexts ...Context) bool {
	if p == nil || len(contexts) == 0 {
		return false
	}

	for _, t := range contexts {
		if p.contains(t) {
			return true
		}
	}

	return false
}

// MarshalJSON marshals the context property.
func (p *ContextProperty) MarshalJSON() ([]byte, error) {
	if len(p.contexts) == 1 {
		return json.Marshal(p.contexts[0])
	}

	return json.Marshal(p.contexts)
}

// UnmarshalJSON unmarshals the context property.
func (p *ContextProperty) UnmarshalJSON(bytes []byte) error {
	var ctx Context

	err := json.Unmarshal(bytes, &ctx)
	if err == nil {
		p.contexts = []Context{ctx}

		return err
	}

	var contexts []Context

	err = json.Unmarshal(bytes, &contexts)
	if err != nil {
		return err
	}

	p.contexts = contexts

	return nil
}

func (p *ContextProperty) contains(t Context) bool {
	for _, pt := range p.contexts {
		if pt == t {
			return true
		}
	}

	return false
}
