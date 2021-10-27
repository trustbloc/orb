/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// LinkType defines the ActivityPub 'Link' type.
type LinkType struct {
	link *linkType
}

type linkType struct {
	HRef *URLProperty `json:"href,omitempty"`
	Rel  []string     `json:"rel,omitempty"`
}

// NewLink creates a new Link type.
func NewLink(hRef *url.URL, rel ...string) *LinkType {
	return &LinkType{
		link: &linkType{
			HRef: NewURLProperty(hRef),
			Rel:  rel,
		},
	}
}

// Type always returns the "Link" type.
func (t *LinkType) Type() *TypeProperty {
	return NewTypeProperty(TypeLink)
}

// HRef return the reference ('href' field).
func (t *LinkType) HRef() *url.URL {
	if t == nil || t.link == nil || t.link.HRef == nil {
		return nil
	}

	return t.link.HRef.URL()
}

// Rel returns the relationship ('rel' field).
func (t *LinkType) Rel() Relationship {
	if t == nil || t.link == nil {
		return nil
	}

	return t.link.Rel
}

// MarshalJSON marshals the link type to JSON.
func (t *LinkType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.link, Document{propertyType: TypeLink})
}

// UnmarshalJSON umarshals the link type from JSON.
func (t *LinkType) UnmarshalJSON(bytes []byte) error {
	t.link = &linkType{}

	return UnmarshalJSON(bytes, &t.link)
}

// Relationship holds the relationship of the Link.
type Relationship []string

// Is return true if the given relationship is contained.
func (r Relationship) Is(relationship string) bool {
	for _, rel := range r {
		if rel == relationship {
			return true
		}
	}

	return false
}
