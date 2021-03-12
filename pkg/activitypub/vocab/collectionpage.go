/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// CollectionPageType defines a "CollectionPage" type.
type CollectionPageType struct {
	*CollectionType

	collPage *collectionPageType
}

type collectionPageType struct {
	PartOf *URLProperty `json:"partOf,omitempty"`
	Next   *URLProperty `json:"next,omitempty"`
	Prev   *URLProperty `json:"prev,omitempty"`
}

// NewCollectionPage returns a new collection page.
func NewCollectionPage(items []*ObjectProperty, opts ...Opt) *CollectionPageType {
	options := NewOptions(opts...)

	t := &CollectionPageType{
		CollectionType: NewCollection(items, opts...),
		collPage: &collectionPageType{
			PartOf: NewURLProperty(options.PartOf),
			Next:   NewURLProperty(options.Next),
			Prev:   NewURLProperty(options.Prev),
		},
	}

	t.object.Type = NewTypeProperty(TypeCollectionPage)

	return t
}

// PartOf return the URL of the collection of which this page is a part.
func (t *CollectionPageType) PartOf() *url.URL {
	return t.collPage.PartOf.URL()
}

// Next return the URL that may be used to retrieve the next page.
func (t *CollectionPageType) Next() *url.URL {
	return t.collPage.Next.URL()
}

// Prev return the URL that may be used to retrieve the previous page.
func (t *CollectionPageType) Prev() *url.URL {
	return t.collPage.Prev.URL()
}

// MarshalJSON marshals the collection page.
func (t *CollectionPageType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.CollectionType, t.collPage)
}

// UnmarshalJSON unmarshals the collection page.
func (t *CollectionPageType) UnmarshalJSON(bytes []byte) error {
	t.CollectionType = &CollectionType{}
	t.collPage = &collectionPageType{}

	return UnmarshalJSON(bytes, t.CollectionType, t.collPage)
}

// OrderedCollectionPageType defines a "OrderedCollectionPage" type.
type OrderedCollectionPageType struct {
	*OrderedCollectionType

	collPage *collectionPageType
}

// NewOrderedCollectionPage returns a new ordered collection page.
func NewOrderedCollectionPage(items []*ObjectProperty, opts ...Opt) *OrderedCollectionPageType {
	options := NewOptions(opts...)

	t := &OrderedCollectionPageType{
		OrderedCollectionType: NewOrderedCollection(items, opts...),
		collPage: &collectionPageType{
			PartOf: NewURLProperty(options.PartOf),
			Next:   NewURLProperty(options.Next),
			Prev:   NewURLProperty(options.Prev),
		},
	}

	t.object.Type = NewTypeProperty(TypeOrderedCollectionPage)

	return t
}

// PartOf return the URL of the collection of which this page is a part.
func (t *OrderedCollectionPageType) PartOf() *url.URL {
	return t.collPage.PartOf.URL()
}

// Next return the URL that may be used to retrieve the next page.
func (t *OrderedCollectionPageType) Next() *url.URL {
	return t.collPage.Next.URL()
}

// Prev return the URL that may be used to retrieve the previous page.
func (t *OrderedCollectionPageType) Prev() *url.URL {
	return t.collPage.Prev.URL()
}

// MarshalJSON marshals the collection page.
func (t *OrderedCollectionPageType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.OrderedCollectionType, t.collPage)
}

// UnmarshalJSON unmarshals the collection page.
func (t *OrderedCollectionPageType) UnmarshalJSON(bytes []byte) error {
	t.OrderedCollectionType = &OrderedCollectionType{}
	t.collPage = &collectionPageType{}

	return UnmarshalJSON(bytes, t.OrderedCollectionType, t.collPage)
}
