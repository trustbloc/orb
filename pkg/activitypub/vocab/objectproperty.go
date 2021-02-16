/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// ObjectProperty defines an 'object' property. The property may be a simple IRI or
// an embedded object such as 'Collection', 'OrderedCollection', 'Activity', etc.
type ObjectProperty struct {
	iri         *URLProperty
	obj         *ObjectType
	coll        *CollectionType
	orderedColl *OrderedCollectionType
}

// NewObjectProperty returns a new 'object' property with the given options.
func NewObjectProperty(opts ...Opt) *ObjectProperty {
	options := NewOptions(opts...)

	return &ObjectProperty{
		iri:         NewURLProperty(options.Iri),
		obj:         options.Object,
		coll:        options.Collection,
		orderedColl: options.OrderedCollection,
	}
}

// Type returns the type of the object property. If the property
// is an IRI then nil is returned.
func (p *ObjectProperty) Type() *TypeProperty {
	if p.obj != nil {
		return p.obj.Type()
	}

	if p.coll != nil {
		return p.coll.Type()
	}

	if p.orderedColl != nil {
		return p.orderedColl.Type()
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

// Collection returns the collection or nil if the collection is not set.
func (p *ObjectProperty) Collection() *CollectionType {
	return p.coll
}

// OrderedCollection returns the ordered collection or nil if the ordered collection is not set.
func (p *ObjectProperty) OrderedCollection() *OrderedCollectionType {
	return p.orderedColl
}

// MarshalJSON marshals the 'object' property.
func (p *ObjectProperty) MarshalJSON() ([]byte, error) {
	if p.iri != nil {
		return json.Marshal(p.iri)
	}

	if p.obj != nil {
		return json.Marshal(p.obj)
	}

	if p.coll != nil {
		return json.Marshal(p.coll)
	}

	if p.orderedColl != nil {
		return json.Marshal(p.orderedColl)
	}

	return nil, fmt.Errorf("nil object property")
}

// UnmarshalJSON unmarshals the 'object' property.
func (p *ObjectProperty) UnmarshalJSON(bytes []byte) error {
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

	if obj.object.Type == nil {
		p.obj = obj

		return nil
	}

	switch {
	case obj.object.Type.Is(TypeCollection):
		err = p.unmarshalCollection(bytes)

	case obj.object.Type.Is(TypeOrderedCollection):
		err = p.unmarshalOrderedCollection(bytes)

	default:
		p.obj = obj
	}

	return err
}

func (p *ObjectProperty) unmarshalCollection(bytes []byte) error {
	coll := &CollectionType{}

	if err := json.Unmarshal(bytes, &coll); err != nil {
		return err
	}

	p.coll = coll

	return nil
}

func (p *ObjectProperty) unmarshalOrderedCollection(bytes []byte) error {
	coll := &OrderedCollectionType{}

	if err := json.Unmarshal(bytes, &coll); err != nil {
		return err
	}

	p.orderedColl = coll

	return nil
}
