/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
)

// AnchorEventType defines an "AnchorEvent" type.
type AnchorEventType struct {
	*ObjectType

	anchorEvent *anchorEventType
}

type anchorEventType struct {
	Index  *URLProperty           `json:"index,omitempty"`
	Parent *URLCollectionProperty `json:"parent,omitempty"`
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
			Index:  NewURLProperty(options.Index),
			Parent: NewURLCollectionProperty(options.Parent...),
		},
	}
}

// Index returns the index URL.
func (t *AnchorEventType) Index() *url.URL {
	if t == nil || t.anchorEvent == nil {
		return nil
	}

	return t.anchorEvent.Index.URL()
}

// Parent returns the parent URLs.
func (t *AnchorEventType) Parent() Urls {
	if t == nil || t.anchorEvent == nil {
		return nil
	}

	return t.anchorEvent.Parent.URLs()
}

// Validate validates the anchor event.
func (t *AnchorEventType) Validate() error {
	if t == nil {
		return fmt.Errorf("nil anchor event")
	}

	if t.Index() == nil {
		if len(t.URL()) > 0 {
			// This is an anchor event reference.
			return nil
		}

		return fmt.Errorf("either anchors or URL is required on anchor event")
	}

	// Validate all attachments and find the attachment that matches the anchor URL.

	var anchorObj *AnchorObjectType

	for _, attachment := range t.Attachment() {
		if !attachment.Type().Is(TypeAnchorObject) {
			return fmt.Errorf("unsupported attachment type [%s] in anchor event", attachment.Type())
		}

		ao := attachment.AnchorObject()

		err := validateAnchorObject(ao)
		if err != nil {
			return fmt.Errorf("invalid anchor object: %w", err)
		}

		if ao.URL()[0].String() == t.Index().String() {
			anchorObj = ao

			break
		}
	}

	if anchorObj == nil {
		return fmt.Errorf("unable to find the attachment that matches the anchors URL in the anchor event [%s]",
			t.Index())
	}

	return nil
}

func validateAnchorObject(anchorObj *AnchorObjectType) error {
	if len(anchorObj.URL()) != 1 {
		return fmt.Errorf("anchor object must have exactly one URL")
	}

	anchorObjURL := anchorObj.URL()[0]

	if anchorObj.Generator() == "" {
		return fmt.Errorf("generator is required in anchor event")
	}

	if anchorObj.ContentObject() == nil {
		return fmt.Errorf("content object is required in anchor event")
	}

	contentObjBytes, err := canonicalizer.MarshalCanonical(anchorObj.ContentObject())
	if err != nil {
		return fmt.Errorf("marshal content object: %w", err)
	}

	hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
	if err != nil {
		return fmt.Errorf("create hashlink from content object: %w", err)
	}

	if hl != anchorObjURL.String() {
		return fmt.Errorf("hashlink of content object [%s] does not match the anchor object URL %s",
			hl, anchorObjURL)
	}

	return nil
}

// AnchorObject returns the AnchorObject for the given AnchorObject URL.
func (t *AnchorEventType) AnchorObject(u *url.URL) (*AnchorObjectType, error) {
	if t == nil || u == nil {
		return nil, orberrors.ErrContentNotFound
	}

	for _, attachment := range t.Attachment() {
		if attachment.AnchorObject().URL().Contains(u) {
			return attachment.AnchorObject(), nil
		}
	}

	return nil, orberrors.ErrContentNotFound
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
	ContentObject Document `json:"contentObject,omitempty"`
}

// NewAnchorObject returns a new AnchorObject type.
func NewAnchorObject(generator string, contentObject Document, opts ...Opt) (*AnchorObjectType, error) {
	options := NewOptions(opts...)

	contentObjBytes, err := json.Marshal(contentObject)
	if err != nil {
		return nil, fmt.Errorf("marshal content object: %w", err)
	}

	hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("create hashlink to content object: %w", err)
	}

	hlURL, err := url.Parse(hl)
	if err != nil {
		return nil, fmt.Errorf("create hashlink URL to content object: %w", err)
	}

	var tag *TagProperty

	if options.Link != nil {
		tag = NewTagProperty(WithLink(options.Link))
	}

	return &AnchorObjectType{
		ObjectType: NewObject(
			WithContext(getContexts(options)...),
			WithType(TypeAnchorObject),
			WithGenerator(generator),
			WithURL(hlURL),
			WithTag(tag),
		),
		anchorObject: &anchorObjectType{
			ContentObject: contentObject,
		},
	}, nil
}

// ContentObject returns the content object.
func (t *AnchorObjectType) ContentObject() Document {
	if t == nil || t.anchorObject == nil {
		return nil
	}

	return t.anchorObject.ContentObject
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
