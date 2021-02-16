/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"net/url"
)

// ObjectProperty defines an 'object' property. The property may be a simple IRI or
// an embedded object such as 'Collection', 'OrderedCollection', 'Activity', etc.
type ObjectProperty struct {
	iri *URLProperty
	obj *ObjectType
}

// NewObjectProperty returns a new 'object' property with the given options.
func NewObjectProperty(opts ...Opt) *ObjectProperty {
	options := NewOptions(opts...)

	return &ObjectProperty{
		iri: NewURLProperty(options.Iri),
		obj: options.Object,
	}
}

// Type returns the type of the object property. If the property
// is an IRI then nil is returned.
func (p *ObjectProperty) Type() *TypeProperty {
	if p.obj != nil {
		return p.obj.Type()
	}

	return nil
}

// IRI returns the IRI or nil if the IRI is not set.
func (p *ObjectProperty) IRI() *url.URL {
	if p.iri == nil {
		return nil
	}

	return p.iri.u
}

// Object returns the object or nil if the object is not set.
func (p *ObjectProperty) Object() *ObjectType {
	return p.obj
}

// MarshalJSON marshals the 'object' property.
func (p *ObjectProperty) MarshalJSON() ([]byte, error) {
	if p.iri != nil {
		return json.Marshal(p.iri)
	}

	if p.obj != nil {
		return json.Marshal(p.obj)
	}

	return nil, nil
}

// UnmarshalJSON unmarshals the 'object' property.
func (p *ObjectProperty) UnmarshalJSON(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}

	iri := &URLProperty{}

	err := json.Unmarshal(bytes, &iri)
	if err == nil {
		p.iri = iri

		return nil
	}

	obj := &ObjectType{}

	err = json.Unmarshal(bytes, &obj)
	if err != nil {
		return err
	}

	p.obj = obj

	return nil
}
