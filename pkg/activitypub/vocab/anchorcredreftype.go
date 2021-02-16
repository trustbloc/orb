/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

// AnchorCredentialReferenceType defines an "AnchorCredentialReference" type.
type AnchorCredentialReferenceType struct {
	*ObjectType

	ref *anchorCredentialReferenceType
}

type anchorCredentialReferenceType struct {
	Target *ObjectProperty `json:"target,omitempty"`
	Object *ObjectProperty `json:"object,omitempty"`
}

// NewAnchorCredentialReference returns a new "AnchorCredentialReference".
func NewAnchorCredentialReference(id, cid string, opts ...Opt) *AnchorCredentialReferenceType {
	options := NewOptions(opts...)

	return &AnchorCredentialReferenceType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextOrb)...),
			WithID(id),
			WithType(TypeAnchorCredentialRef),
		),
		ref: &anchorCredentialReferenceType{
			Target: NewObjectProperty(
				WithObject(
					NewObject(
						WithID(cid), WithType(TypeCAS),
					),
				),
			),
		},
	}
}

// NewAnchorCredentialReferenceWithDocument returns a new "AnchorCredentialReference" with the given document embedded.
func NewAnchorCredentialReferenceWithDocument(
	id, cid string, doc Document, opts ...Opt) (*AnchorCredentialReferenceType, error) {
	options := NewOptions(opts...)

	obj, err := NewObjectWithDocument(doc)
	if err != nil {
		return nil, err
	}

	return &AnchorCredentialReferenceType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextOrb)...),
			WithID(id),
			WithType(TypeAnchorCredentialRef),
		),
		ref: &anchorCredentialReferenceType{
			Target: NewObjectProperty(
				WithObject(
					NewObject(
						WithID(cid), WithType(TypeCAS),
					),
				),
			),
			Object: NewObjectProperty(
				WithObject(obj),
			),
		},
	}, nil
}

// Target returns the target of the anchor credential reference.
func (t *AnchorCredentialReferenceType) Target() *ObjectProperty {
	return t.ref.Target
}

// Object returns the embedded object (if any).
func (t *AnchorCredentialReferenceType) Object() *ObjectProperty {
	return t.ref.Object
}

// MarshalJSON mmarshals the object to JSON.
func (t *AnchorCredentialReferenceType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.ref)
}

// UnmarshalJSON ummarshals the object from JSON.
func (t *AnchorCredentialReferenceType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.ref = &anchorCredentialReferenceType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.ref)
}
