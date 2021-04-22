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
			Context:   NewContextProperty(options.Context...),
			ID:        NewURLProperty(options.ID),
			CID:       options.CID,
			Type:      NewTypeProperty(options.Types...),
			To:        NewURLCollectionProperty(options.To...),
			Published: options.Published,
			StartTime: options.StartTime,
			EndTime:   options.EndTime,
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
	Context   *ContextProperty       `json:"@context,omitempty"`
	ID        *URLProperty           `json:"id,omitempty"`
	Type      *TypeProperty          `json:"type,omitempty"`
	To        *URLCollectionProperty `json:"to,omitempty"`
	Published *time.Time             `json:"published,omitempty"`
	StartTime *time.Time             `json:"startTime,omitempty"`
	EndTime   *time.Time             `json:"endTime,omitempty"`
	CID       string                 `json:"cid,omitempty"`
}

// Context returns the context property.
func (t *ObjectType) Context() *ContextProperty {
	return t.object.Context
}

// ID returns the object's ID.
func (t *ObjectType) ID() *URLProperty {
	return t.object.ID
}

// SetID sets the object's ID.
func (t *ObjectType) SetID(id *url.URL) {
	t.object.ID = NewURLProperty(id)
}

// Type returns the type of the object.
func (t *ObjectType) Type() *TypeProperty {
	return t.object.Type
}

// Published returns the time when the object was published.
func (t *ObjectType) Published() *time.Time {
	return t.object.Published
}

// StartTime returns the start time.
func (t *ObjectType) StartTime() *time.Time {
	return t.object.StartTime
}

// EndTime returns the end time.
func (t *ObjectType) EndTime() *time.Time {
	return t.object.EndTime
}

// To returns a set of URLs to which the object should be sent.
func (t *ObjectType) To() []*url.URL {
	if t.object.To == nil {
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
	return t.object.CID
}

// Value returns the value of a property.
func (t *ObjectType) Value(key string) (interface{}, bool) {
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
