/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// CollectionType defines a "Collection" type.
type CollectionType struct {
	*ObjectType

	coll *collectionType
}

type collectionType struct {
	Current    *URLProperty      `json:"current,omitempty"`
	First      *URLProperty      `json:"first,omitempty"`
	Last       *URLProperty      `json:"last,omitempty"`
	TotalItems int               `json:"totalItems,omitempty"`
	Items      []*ObjectProperty `json:"items,omitempty"`
}

// TotalItems returns the total number of items in the collection.
func (t *CollectionType) TotalItems() int {
	return t.coll.TotalItems
}

// Items returns the items in the collection.
func (t *CollectionType) Items() []*ObjectProperty {
	items := make([]*ObjectProperty, len(t.coll.Items))

	for i, item := range t.coll.Items {
		items[i] = item
	}

	return items
}

// Current returns the current item.
func (t *CollectionType) Current() *url.URL {
	return t.coll.Current.u
}

// First returns a URL that may be used to retrieve the first item in the collection.
func (t *CollectionType) First() *url.URL {
	return t.coll.First.u
}

// Last returns a URL that may be used to retrieve the last item in the collection.
func (t *CollectionType) Last() *url.URL {
	return t.coll.Last.u
}

// NewCollection returns a new collection.
func NewCollection(items []*ObjectProperty, opts ...Opt) *CollectionType {
	options := NewOptions(opts...)

	totalItems := options.TotalItems
	if totalItems == 0 {
		totalItems = len(items)
	}

	return &CollectionType{
		ObjectType: NewObject(
			WithContext(options.Context...),
			WithID(options.ID),
			WithType(TypeCollection),
		),
		coll: &collectionType{
			Current:    NewURLProperty(options.Current),
			First:      NewURLProperty(options.First),
			Last:       NewURLProperty(options.Last),
			TotalItems: totalItems,
			Items:      items,
		},
	}
}

// MarshalJSON marshals the object to JSON.
func (t *CollectionType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.coll)
}

// UnmarshalJSON unmarshals the object from JSON.
func (t *CollectionType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.coll = &collectionType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.coll)
}

// OrderedCollectionType defines an "OrderedCollection" type.
type OrderedCollectionType struct {
	*CollectionType

	orderedColl *orderedCollectionType
}

// NewOrderedCollection returns a new ordered collection.
func NewOrderedCollection(items []*ObjectProperty, opts ...Opt) *OrderedCollectionType {
	t := &OrderedCollectionType{
		CollectionType: NewCollection(nil, opts...),
		orderedColl:    &orderedCollectionType{OrderedItems: items},
	}

	t.object.Type = NewTypeProperty(TypeOrderedCollection)

	options := NewOptions(opts...)

	totalItems := options.TotalItems
	if totalItems == 0 {
		totalItems = len(items)
	}

	t.coll.TotalItems = totalItems

	return t
}

type orderedCollectionType struct {
	OrderedItems []*ObjectProperty `json:"orderedItems,omitempty"`
}

// Items returns the items in the ordered collection.
func (t *OrderedCollectionType) Items() []*ObjectProperty {
	items := make([]*ObjectProperty, len(t.orderedColl.OrderedItems))

	for i, item := range t.orderedColl.OrderedItems {
		items[i] = item
	}

	return items
}

// MarshalJSON marshals the ordered collection.
func (t *OrderedCollectionType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.CollectionType, t.orderedColl)
}

// UnmarshalJSON unmarshals the ordered collection.
func (t *OrderedCollectionType) UnmarshalJSON(bytes []byte) error {
	t.CollectionType = &CollectionType{}
	t.orderedColl = &orderedCollectionType{}

	return UnmarshalJSON(bytes, t.CollectionType, t.orderedColl)
}
