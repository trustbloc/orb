/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/hashlink"
)

// AnchorEventType defines an "AnchorReference" type.
type AnchorEventType struct {
	*ObjectType

	anchorEvent *anchorEventType
}

type anchorEventType struct {
	Anchors *URLProperty           `json:"anchors,omitempty"`
	Parent  *URLCollectionProperty `json:"parent,omitempty"`
}

// NewAnchorEvent returns a new Info type.
func NewAnchorEvent(opts ...Opt) *AnchorEventType {
	options := NewOptions(opts...)

	return &AnchorEventType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityAnchors)...),
			WithType(TypeAnchorEvent),
			WithPublishedTime(options.Published),
			WithURL(options.URL...),
			WithAttributedTo(options.AttributedTo),
			WithAttachment(options.Attachment...)),
		anchorEvent: &anchorEventType{
			Anchors: NewURLProperty(options.Anchors),
			Parent:  NewURLCollectionProperty(options.Parent...),
		},
	}
}

// Anchors returns the anchor URL.
func (t *AnchorEventType) Anchors() *url.URL {
	if t == nil || t.anchorEvent == nil {
		return nil
	}

	return t.anchorEvent.Anchors.URL()
}

// Parent returns the parent URLs.
func (t *AnchorEventType) Parent() Urls {
	if t == nil || t.anchorEvent == nil {
		return nil
	}

	return t.anchorEvent.Parent.URLs()
}

// Validate validates the anchor event.
func (t *AnchorEventType) Validate() error { //nolint:gocyclo,cyclop
	if t == nil {
		return fmt.Errorf("nil anchor event")
	}

	if t.Anchors() == nil {
		if len(t.URL()) > 0 {
			// This is an anchor event reference.
			return nil
		}

		return fmt.Errorf("either anchors or URL is required on anchor event")
	}

	if len(t.Attachment()) != 1 {
		return fmt.Errorf("anchor event must have exactly one attachment but has %d",
			len(t.Attachment()))
	}

	attachment := t.Attachment()[0]

	if !attachment.Type().Is(TypeAnchorObject) {
		return fmt.Errorf("unsupported attachment type [%s] in anchor event", attachment.Type())
	}

	anchorObj := attachment.AnchorObject()

	if len(anchorObj.URL()) != 1 {
		return fmt.Errorf("anchor object must have exactly one URL")
	}

	if !anchorObj.URL().Contains(t.Anchors()) {
		return fmt.Errorf("anchor object URL %s must be the same as the anchors URL in the anchor event URL %s",
			anchorObj.URL(), t.Anchors())
	}

	if anchorObj.ContentObject() == nil {
		return fmt.Errorf("content object is required in anchor event")
	}

	err := validateAnchorsURL(t.Anchors(), anchorObj.ContentObject())
	if err != nil {
		return fmt.Errorf("invalid anchors URL: %w", err)
	}

	if anchorObj.Witness().Object() == nil {
		return fmt.Errorf("witness is required in anchor event")
	}

	return nil
}

func validateAnchorsURL(anchorsURL *url.URL, contentObj *ContentObjectType) error {
	contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
	if err != nil {
		return fmt.Errorf("marshal content object: %w", err)
	}

	hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
	if err != nil {
		return fmt.Errorf("create hashlink from content object: %w", err)
	}

	if hl != anchorsURL.String() {
		return fmt.Errorf("hashlink of content object [%s] does not match the anchor object URL %s",
			hl, anchorsURL)
	}

	return nil
}

// Witness returns the "Witness" verifiable credential.
func (t *AnchorEventType) Witness() *ObjectType {
	if t == nil || len(t.Attachment()) == 0 {
		return nil
	}

	return t.Attachment()[0].AnchorObject().Witness().Object()
}

// ContentObject returns the ContentObject.
func (t *AnchorEventType) ContentObject() *ContentObjectType {
	if t == nil || len(t.Attachment()) == 0 {
		return nil
	}

	return t.Attachment()[0].AnchorObject().ContentObject()
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

// AnchorObjectType defines an "AnchorReference" type.
type AnchorObjectType struct {
	*ObjectType

	anchorObject *anchorObjectType
}

type anchorObjectType struct {
	ContentObject *ContentObjectType `json:"contentObject,omitempty"`
	Witness       *ObjectProperty    `json:"witness,omitempty"`
}

// NewAnchorObject returns a new AnchorObject type.
func NewAnchorObject(contentObject *ContentObjectType, witness *ObjectType, opts ...Opt) *AnchorObjectType {
	options := NewOptions(opts...)

	return &AnchorObjectType{
		ObjectType: NewObject(
			WithContext(getContexts(options)...),
			WithType(TypeAnchorObject),
			WithPublishedTime(options.Published),
			WithURL(options.URL...),
			WithAttachment(options.Attachment...)),
		anchorObject: &anchorObjectType{
			ContentObject: contentObject,
			Witness:       NewObjectProperty(WithObject(witness)),
		},
	}
}

// ContentObject returns the content object.
func (t *AnchorObjectType) ContentObject() *ContentObjectType {
	if t == nil || t.anchorObject == nil {
		return nil
	}

	return t.anchorObject.ContentObject
}

// Witness returns the verifiable credential.
func (t *AnchorObjectType) Witness() *ObjectProperty {
	if t == nil || t.anchorObject == nil {
		return nil
	}

	return t.anchorObject.Witness
}

// MarshalJSON marshals the object to JSON.
func (t *AnchorObjectType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.anchorObject)
}

// UnmarshalJSON umarshals the object from JSON.
func (t *AnchorObjectType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.anchorObject = &anchorObjectType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.anchorObject)
}

type propertiesType struct {
	Generator string      `json:"https://w3id.org/activityanchors#generator,omitempty"`
	Resources []*Resource `json:"https://w3id.org/activityanchors#resources,omitempty"`
}

// ContentObjectType defines an "AnchorReference" type.
type ContentObjectType struct {
	Subject    *URLProperty    `json:"subject,omitempty"`
	Properties *propertiesType `json:"properties,omitempty"`
}

// NewContentObject returns a new ContentObject type.
func NewContentObject(generator string, subject *url.URL, resources ...*Resource) *ContentObjectType {
	return &ContentObjectType{
		Subject: NewURLProperty(subject),
		Properties: &propertiesType{
			Generator: generator,
			Resources: resources,
		},
	}
}

// Generator returns the ID of the generator.
func (t *ContentObjectType) Generator() string {
	if t == nil || t.Properties == nil {
		return ""
	}

	return t.Properties.Generator
}

// Resources returns the resources of the content object.
func (t *ContentObjectType) Resources() []*Resource {
	if t == nil {
		return nil
	}

	return t.Properties.Resources
}

// Resource defines a Resource.
type Resource struct {
	ID             string `json:"id"`
	PreviousAnchor string `json:"previousAnchor,omitempty"`
}

// NewResource returns a new Resource type.
func NewResource(id, previousAnchor string) *Resource {
	return &Resource{
		ID:             id,
		PreviousAnchor: previousAnchor,
	}
}
