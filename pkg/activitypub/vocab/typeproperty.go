/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
)

// TypeProperty defines a 'type' property on an abject which
// can hold one or more types.
type TypeProperty struct {
	types []Type
}

// NewTypeProperty returns a new 'type' property. Nil is returned if no types were provided.
func NewTypeProperty(t ...Type) *TypeProperty {
	if len(t) == 0 {
		return nil
	}

	return &TypeProperty{types: t}
}

// MarshalJSON marshals the type property.
func (p *TypeProperty) MarshalJSON() ([]byte, error) {
	if len(p.types) == 1 {
		return json.Marshal(p.types[0])
	}

	return json.Marshal(p.types)
}

// UnmarshalJSON unmarshals the type property.
func (p *TypeProperty) UnmarshalJSON(bytes []byte) error {
	var ctx Type

	err := json.Unmarshal(bytes, &ctx)
	if err == nil {
		p.types = []Type{ctx}

		return err
	}

	var types []Type

	err = json.Unmarshal(bytes, &types)
	if err != nil {
		return err
	}

	p.types = types

	return nil
}

// Types returns all types.
func (p *TypeProperty) Types() []Type {
	return p.types
}

// Is returns true if the property has all of the given types.
func (p *TypeProperty) Is(types ...Type) bool {
	if len(types) == 0 {
		return false
	}

	for _, t := range types {
		if !p.is(t) {
			return false
		}
	}

	return true
}

// IsAny returns true if the property has any of the given types.
func (p *TypeProperty) IsAny(types ...Type) bool {
	for _, t := range types {
		if p.Is(t) {
			return true
		}
	}

	return false
}

func (p *TypeProperty) is(t Type) bool {
	for _, pt := range p.types {
		if pt == t {
			return true
		}
	}

	return false
}
