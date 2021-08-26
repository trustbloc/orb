/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// AnchorReferenceType defines an "AnchorReference" type.
type AnchorReferenceType struct {
	*ObjectType

	ref *anchorReferenceType
}

type anchorReferenceType struct {
	Target *ObjectProperty        `json:"target,omitempty"`
	Object *ObjectProperty        `json:"object,omitempty"`
	URL    *URLCollectionProperty `json:"url,omitempty"`
}

// NewAnchorReference returns a new "AnchorReference".
func NewAnchorReference(id, anchorCredID *url.URL, cid string, opts ...Opt) *AnchorReferenceType {
	options := NewOptions(opts...)

	return &AnchorReferenceType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextActivityAnchors)...),
			WithID(id),
			WithType(TypeAnchorRef),
		),
		ref: &anchorReferenceType{
			Target: NewObjectProperty(
				WithObject(
					NewObject(
						WithID(anchorCredID), WithCID(cid), WithType(TypeContentAddressedStorage),
					),
				),
			),
		},
	}
}

// NewAnchorReferenceWithDocument returns a new "AnchorReference" with the given document embedded.
func NewAnchorReferenceWithDocument(
	id, anchorCredID *url.URL, cid string, doc Document, opts ...Opt) (*AnchorReferenceType, error) {
	options := NewOptions(opts...)

	obj, err := NewObjectWithDocument(doc)
	if err != nil {
		return nil, err
	}

	return &AnchorReferenceType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextActivityAnchors)...),
			WithID(id),
			WithType(TypeAnchorRef),
		),
		ref: &anchorReferenceType{
			Target: NewObjectProperty(
				WithObject(
					NewObject(
						WithID(anchorCredID), WithCID(cid), WithType(TypeContentAddressedStorage),
					),
				),
			),
			Object: NewObjectProperty(
				WithObject(obj),
			),
		},
	}, nil
}

// NewAnchorReferenceWithOpts returns a new "AnchorReference".
func NewAnchorReferenceWithOpts(opts ...Opt) *AnchorReferenceType {
	options := NewOptions(opts...)

	return &AnchorReferenceType{
		ObjectType: NewObject(
			WithType(TypeAnchorRef),
			WithURL(options.URL...),
			WithAttachment(options.Attachment...),
		),
	}
}

// Target returns the target of the anchor credential reference.
func (t *AnchorReferenceType) Target() *ObjectProperty {
	if t == nil || t.ref == nil {
		return nil
	}

	return t.ref.Target
}

// Object returns the embedded object (if any).
func (t *AnchorReferenceType) Object() *ObjectProperty {
	if t == nil || t.ref == nil {
		return nil
	}

	return t.ref.Object
}

// MarshalJSON mmarshals the object to JSON.
func (t *AnchorReferenceType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.ref)
}

// UnmarshalJSON ummarshals the object from JSON.
func (t *AnchorReferenceType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.ref = &anchorReferenceType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.ref)
}
