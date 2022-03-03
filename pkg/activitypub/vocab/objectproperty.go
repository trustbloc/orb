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
	iri          *URLProperty
	obj          *ObjectType
	coll         *CollectionType
	orderedColl  *OrderedCollectionType
	activity     *ActivityType
	anchorObject *AnchorObjectType
	anchorEvent  *AnchorEventType
}

// NewObjectProperty returns a new 'object' property with the given options.
func NewObjectProperty(opts ...Opt) *ObjectProperty {
	options := NewOptions(opts...)

	return &ObjectProperty{
		iri:          NewURLProperty(options.Iri),
		obj:          options.Object,
		coll:         options.Collection,
		orderedColl:  options.OrderedCollection,
		activity:     options.Activity,
		anchorObject: options.AnchorObject,
		anchorEvent:  options.AnchorEvent,
	}
}

// Type returns the type of the object property. If the property
// is an IRI then nil is returned.
func (p *ObjectProperty) Type() *TypeProperty {
	if p == nil {
		return nil
	}

	if p.obj != nil {
		return p.obj.Type()
	}

	if p.coll != nil {
		return p.coll.Type()
	}

	if p.orderedColl != nil {
		return p.orderedColl.Type()
	}

	if p.activity != nil {
		return p.activity.Type()
	}

	if p.anchorObject != nil {
		return p.anchorObject.Type()
	}

	if p.anchorEvent != nil {
		return p.anchorEvent.Type()
	}

	return nil
}

// IRI returns the IRI or nil if the IRI is not set.
func (p *ObjectProperty) IRI() *url.URL {
	if p == nil || p.iri == nil {
		return nil
	}

	return p.iri.URL()
}

// Object returns the object or nil if the object is not set.
func (p *ObjectProperty) Object() *ObjectType {
	if p == nil {
		return nil
	}

	return p.obj
}

// Collection returns the collection or nil if the collection is not set.
func (p *ObjectProperty) Collection() *CollectionType {
	if p == nil {
		return nil
	}

	return p.coll
}

// OrderedCollection returns the ordered collection or nil if the ordered collection is not set.
func (p *ObjectProperty) OrderedCollection() *OrderedCollectionType {
	if p == nil {
		return nil
	}

	return p.orderedColl
}

// Activity returns the activity or nil if the activity is not set.
func (p *ObjectProperty) Activity() *ActivityType {
	if p == nil {
		return nil
	}

	return p.activity
}

// AnchorObject returns the anchor object or nil if
// the anchor object is not set.
func (p *ObjectProperty) AnchorObject() *AnchorObjectType {
	if p == nil {
		return nil
	}

	return p.anchorObject
}

// AnchorEvent returns the anchor event or nil if
// the anchor event is not set.
func (p *ObjectProperty) AnchorEvent() *AnchorEventType {
	if p == nil {
		return nil
	}

	return p.anchorEvent
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

	if p.activity != nil {
		return json.Marshal(p.activity)
	}

	if p.anchorObject != nil {
		return json.Marshal(p.anchorObject)
	}

	if p.anchorEvent != nil {
		return json.Marshal(p.anchorEvent)
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

	case obj.object.Type.IsActivity():
		err = p.unmarshalActivity(bytes)

	case obj.object.Type.Is(TypeAnchorObject):
		err = p.unmarshalAnchorObject(bytes)

	case obj.object.Type.Is(TypeAnchorEvent):
		err = p.unmarshalAnchorEvent(bytes)

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

func (p *ObjectProperty) unmarshalActivity(bytes []byte) error {
	a := &ActivityType{}

	if err := json.Unmarshal(bytes, &a); err != nil {
		return err
	}

	p.activity = a

	return nil
}

func (p *ObjectProperty) unmarshalAnchorObject(bytes []byte) error {
	ao := &AnchorObjectType{}

	if err := json.Unmarshal(bytes, &ao); err != nil {
		return err
	}

	p.anchorObject = ao

	return nil
}

func (p *ObjectProperty) unmarshalAnchorEvent(bytes []byte) error {
	ae := &AnchorEventType{}

	if err := json.Unmarshal(bytes, &ae); err != nil {
		return err
	}

	p.anchorEvent = ae

	return nil
}
