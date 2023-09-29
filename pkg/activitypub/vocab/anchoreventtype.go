/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"fmt"

	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/hashlink"
)

// AnchorEventType defines an "AnchorEvent" type.
type AnchorEventType struct {
	*ObjectType

	anchorEvent *anchorEventType
}

type anchorEventType struct {
	Object *ObjectProperty `json:"object,omitempty"`
}

// NewAnchorEvent returns a new AnchorEvent type.
func NewAnchorEvent(obj *ObjectProperty, opts ...Opt) *AnchorEventType {
	options := NewOptions(opts...)

	return &AnchorEventType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityAnchors)...),
			WithType(TypeAnchorEvent),
			WithURL(options.URL...),
		),
		anchorEvent: &anchorEventType{
			Object: obj,
		},
	}
}

// Object returns the Object property.
func (t *AnchorEventType) Object() *ObjectProperty {
	if t == nil || t.anchorEvent == nil {
		return nil
	}

	return t.anchorEvent.Object
}

// Validate validates the anchor event.
func (t *AnchorEventType) Validate() error {
	if t == nil {
		return fmt.Errorf("nil anchor event")
	}

	if len(t.URL()) != 1 {
		return fmt.Errorf("url is required")
	}

	if t.Object() == nil {
		// Object is optional.
		return nil
	}

	doc := t.Object().Document()

	docBytes, err := canonicalizer.MarshalCanonical(doc)
	if err != nil {
		return fmt.Errorf("marshal document: %w", err)
	}

	hlClient := hashlink.New()

	hlInfo, err := hlClient.ParseHashLink(t.URL()[0].String())
	if err != nil {
		return fmt.Errorf("parse hashlink: %w", err)
	}

	hash, err := hlClient.CreateResourceHash(docBytes)
	if err != nil {
		return fmt.Errorf("create resource hash: %w", err)
	}

	if hlInfo.ResourceHash != hash {
		return fmt.Errorf("hash or URL [%s] does not match the hash of the object [%s]",
			hlInfo.ResourceHash, hash)
	}

	return nil
}

// MarshalJSON marshals the object to JSON.
func (t *AnchorEventType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.anchorEvent)
}

// UnmarshalJSON umarshals the object from JSON.
func (t *AnchorEventType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.anchorEvent = &anchorEventType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.anchorEvent)
}
