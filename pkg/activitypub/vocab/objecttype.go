/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
)

// ObjectType defines an 'object'.
type ObjectType struct {
	object     *objectType
	additional Document
}

// NewObject returns a new 'object'.
func NewObject(opts ...Opt) *ObjectType {
	options := NewOptions(opts...)

	return &ObjectType{
		object: &objectType{
			Context:      NewContextProperty(options.Context...),
			ID:           NewURLProperty(options.ID),
			URL:          NewURLCollectionProperty(options.URL...),
			CID:          options.CID,
			Type:         NewTypeProperty(options.Types...),
			To:           NewURLCollectionProperty(options.To...),
			Published:    newTimeProperty(options.Published),
			StartTime:    newTimeProperty(options.StartTime),
			EndTime:      newTimeProperty(options.EndTime),
			InReplyTo:    NewURLProperty(options.InReplyTo),
			Attachment:   options.Attachment,
			AttributedTo: NewURLProperty(options.AttributedTo),
			Generator:    options.Generator,
			Tag:          options.Tag,
		},
	}
}

// NewObjectWithDocument returns a new object initialized with the given document.
func NewObjectWithDocument(doc Document, opts ...Opt) (*ObjectType, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil document")
	}

	bytes, err := MarshalJSON(NewObject(opts...), doc)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	obj := &ObjectType{}

	err = json.Unmarshal(bytes, &obj)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return obj, nil
}

type objectType struct {
	Context      *ContextProperty       `json:"@context,omitempty"`
	ID           *URLProperty           `json:"id,omitempty"`
	URL          *URLCollectionProperty `json:"url,omitempty"`
	Type         *TypeProperty          `json:"type,omitempty"`
	To           *URLCollectionProperty `json:"to,omitempty"`
	Published    *util.TimeWrapper      `json:"published,omitempty"`
	StartTime    *util.TimeWrapper      `json:"startTime,omitempty"`
	EndTime      *util.TimeWrapper      `json:"endTime,omitempty"`
	CID          string                 `json:"cid,omitempty"`
	InReplyTo    *URLProperty           `json:"inReplyTo,omitempty"`
	Attachment   []*ObjectProperty      `json:"attachment,omitempty"`
	AttributedTo *URLProperty           `json:"attributedTo,omitempty"`
	Generator    string                 `json:"generator,omitempty"`
	Tag          []*TagProperty         `json:"tag,omitempty"`
}

// Context returns the context property.
func (t *ObjectType) Context() *ContextProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.Context
}

// ID returns the object's ID.
func (t *ObjectType) ID() *URLProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.ID
}

// SetID sets the object's ID.
func (t *ObjectType) SetID(id *url.URL) {
	t.object.ID = NewURLProperty(id)
}

// URL returns the object's URLs.
func (t *ObjectType) URL() Urls {
	if t == nil || t.object == nil || t.object.URL == nil {
		return nil
	}

	urls := make([]*url.URL, len(t.object.URL.urls))

	for i, u := range t.object.URL.urls {
		urls[i] = u.u
	}

	return urls
}

// Type returns the type of the object.
func (t *ObjectType) Type() *TypeProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.Type
}

// Published returns the time when the object was published.
func (t *ObjectType) Published() *time.Time {
	if t == nil || t.object == nil || t.object.Published == nil {
		return nil
	}

	return &t.object.Published.Time
}

// StartTime returns the start time.
func (t *ObjectType) StartTime() *time.Time {
	if t == nil || t.object == nil || t.object.StartTime == nil {
		return nil
	}

	return &t.object.StartTime.Time
}

// EndTime returns the end time.
func (t *ObjectType) EndTime() *time.Time {
	if t == nil || t.object == nil || t.object.EndTime == nil {
		return nil
	}

	return &t.object.EndTime.Time
}

// InReplyTo returns the 'inReplyTo' field.
func (t *ObjectType) InReplyTo() *URLProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.InReplyTo
}

// Attachment returns the 'attachment' field.
func (t *ObjectType) Attachment() []*ObjectProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.Attachment
}

// AttributedTo returns the 'attributedTo' field.
func (t *ObjectType) AttributedTo() *URLProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.AttributedTo
}

// Generator returns the 'generator' field.
func (t *ObjectType) Generator() string {
	if t == nil || t.object == nil {
		return ""
	}

	return t.object.Generator
}

// Tag returns the 'tag' field.
func (t *ObjectType) Tag() []*TagProperty {
	if t == nil || t.object == nil {
		return nil
	}

	return t.object.Tag
}

// Urls holds a collection of URLs.
type Urls []*url.URL

// Contains returns true if the collection of URLs contains the given URLs.
func (u Urls) Contains(values ...fmt.Stringer) bool {
	for _, v := range values {
		if !u.contains(v) {
			return false
		}
	}

	return true
}

// Equals returns true if the given collection of URLs is the same as this one. (Order does not matter.)
func (u Urls) Equals(urls Urls) bool {
	if len(urls) != len(u) {
		return false
	}

	for _, v := range urls {
		if !u.contains(v) {
			return false
		}
	}

	return true
}

func (u Urls) contains(v fmt.Stringer) bool {
	for _, iri := range u {
		if iri.String() == v.String() {
			return true
		}
	}

	return false
}

// To returns a set of URLs to which the object should be sent.
func (t *ObjectType) To() Urls {
	if t == nil || t.object == nil || t.object.To == nil {
		return nil
	}

	urls := make([]*url.URL, len(t.object.To.urls))

	for i, u := range t.object.To.urls {
		urls[i] = u.u
	}

	return urls
}

// CID returns the object's content ID.
func (t *ObjectType) CID() string {
	if t == nil || t.object == nil {
		return ""
	}

	return t.object.CID
}

// Value returns the value of a property.
func (t *ObjectType) Value(key string) (interface{}, bool) {
	if t == nil {
		return nil, false
	}

	v, ok := t.additional[key]

	return v, ok
}

// MarshalJSON marshals the object.
func (t *ObjectType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.object, t.additional)
}

// UnmarshalJSON unmarshals the object.
func (t *ObjectType) UnmarshalJSON(bytes []byte) error {
	header := &objectType{}

	err := json.Unmarshal(bytes, header)
	if err != nil {
		return err
	}

	doc := make(Document)

	err = json.Unmarshal(bytes, &doc)
	if err != nil {
		return err
	}

	// Delete all of the reserved ActivityStreams fields
	for _, prop := range reservedProperties() {
		delete(doc, prop)
	}

	t.object = header
	t.additional = doc

	return nil
}

func newTimeProperty(t *time.Time) *util.TimeWrapper {
	if t == nil {
		return nil
	}

	return util.NewTime(*t)
}
