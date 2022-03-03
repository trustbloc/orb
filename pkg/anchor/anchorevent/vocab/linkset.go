/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/hashlink"
)

// LinkType defines the type of the link.
type LinkType = string

const (
	// TypeLinkset indicates that the content type is a linkset in JSON format.
	TypeLinkset LinkType = "application/linkset+json"
	// TypeJSONLD indicates that the content type is JSON LD.
	TypeJSONLD LinkType = "application/ld+json"
)

// AnchorLinkset contains a linkset of AnchorLink objects.
type AnchorLinkset struct {
	Linkset []*AnchorLink `json:"linkset"`
}

// NewAnchorLinkset returns a new AnchorLinkset.
func NewAnchorLinkset(linkset ...*AnchorLink) *AnchorLinkset {
	return &AnchorLinkset{
		Linkset: linkset,
	}
}

// AnchorLink is a link to an anchor object which contains items, parent items, and other metadata.
type AnchorLink struct {
	link *anchorLink
}

type anchorLink struct {
	Anchor  *vocab.URLProperty     `json:"anchor"`
	Author  *vocab.URLProperty     `json:"author"`
	Profile *vocab.URLProperty     `json:"profile"`
	Item    []*Item                `json:"item"`
	Up      *urlCollectionProperty `json:"up"`
}

// NewAnchorLink returns a new AnchorLink.
func NewAnchorLink(anchor, author, profile *url.URL, item []*Item, up []*url.URL) *AnchorLink {
	return &AnchorLink{
		link: &anchorLink{
			Anchor:  vocab.NewURLProperty(anchor),
			Author:  vocab.NewURLProperty(author),
			Item:    item,
			Up:      newURLCollectionProperty(up...),
			Profile: vocab.NewURLProperty(profile),
		},
	}
}

// Anchor returns the anchor URI.
func (l *AnchorLink) Anchor() *url.URL {
	if l == nil {
		return nil
	}

	return l.link.Anchor.URL()
}

// Author returns the originator of the anchor.
func (l *AnchorLink) Author() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Author.URL()
}

// Items returns the items contained within the link.
func (l *AnchorLink) Items() []*Item {
	if l == nil {
		return nil
	}

	return l.link.Item
}

// Up returns the parent items.
func (l *AnchorLink) Up() []*url.URL {
	if l == nil {
		return nil
	}

	return l.link.Up.URLs()
}

// Profile returns the profile used to generate the link.
func (l *AnchorLink) Profile() *url.URL {
	if l == nil {
		return nil
	}

	return l.link.Profile.URL()
}

// Validate validates the AnchorLink.
func (l *AnchorLink) Validate() error {
	if l == nil || l.link == nil {
		return errors.New("nil link")
	}

	if l.Anchor() == nil {
		return errors.New("anchor URI is required")
	}

	if l.Author() == nil {
		return errors.New("author URI is required")
	}

	if l.Profile() == nil {
		return errors.New("profile URI is required")
	}

	if len(l.Items()) == 0 {
		return errors.New("at least one item is required")
	}

	return nil
}

// MarshalJSON marshals the object to JSON.
func (l *AnchorLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.link)
}

// UnmarshalJSON umarshals the object from JSON.
func (l *AnchorLink) UnmarshalJSON(b []byte) error {
	l.link = &anchorLink{}

	return json.Unmarshal(b, l.link)
}

// AnchorLinksetWithReplies contains the original anchor linkset along with replies.
// TODO: Think of a better name.
type AnchorLinksetWithReplies struct {
	Linkset []*AnchorLinkWithReplies `json:"linkset"`
}

// NewAnchorLinksetWithReplies returns a new AnchorLinksetWithReplies.
// TODO: Think of a better name.
func NewAnchorLinksetWithReplies(linkset ...*AnchorLinkWithReplies) *AnchorLinksetWithReplies {
	return &AnchorLinksetWithReplies{
		Linkset: linkset,
	}
}

// AnchorLinkWithReplies contains the original anchor link along with replies.
// TODO: Think of a better name.
type AnchorLinkWithReplies struct {
	link *anchorLinkWithReplies
}

type anchorLinkWithReplies struct {
	Anchor   *vocab.URLProperty `json:"anchor"`
	Original *Reference         `json:"original"`
	Profile  *vocab.URLProperty `json:"profile"`
	Replies  []*Reference       `json:"replies,omitempty"`
}

// LinksetOptions holds the options for a linkset.
type LinksetOptions struct {
	Replies []*Reference
}

// WithReply sets the 'Replies' property.
func WithReply(replies ...*Reference) Opt {
	return func(opts *Options) {
		opts.Replies = replies
	}
}

// Options holds the options for building a linkset.
type Options struct {
	Replies []*Reference
}

// Opt is an option for an object.
type Opt func(opts *Options)

// NewOptions returns an Options struct which is populated with the provided options.
func NewOptions(opts ...Opt) *Options {
	options := &Options{}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// NewAnchorLinkWithReplies returns a new AnchorLinkWithReplies.
// TODO: Think of a better name.
func NewAnchorLinkWithReplies(anchor, profile *url.URL, original *Reference, opts ...Opt) *AnchorLinkWithReplies {
	options := NewOptions(opts...)

	return &AnchorLinkWithReplies{
		link: &anchorLinkWithReplies{
			Anchor:   vocab.NewURLProperty(anchor),
			Original: original,
			Replies:  options.Replies,
			Profile:  vocab.NewURLProperty(profile),
		},
	}
}

// NewAnchorRef creates a data URI Reference of the given content type and returns the anchor URI
// (which is a hashlink of the data).
func NewAnchorRef(data []byte, uriMediaType MediaType, contentType LinkType) (*url.URL, *Reference, error) {
	anchorHL, err := hashlink.New().CreateHashLink(data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create hashlink of data: %w", err)
	}

	anchorURI, err := url.Parse(anchorHL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse anchorURI hashlink: %w", err)
	}

	dataURI, err := NewDataURI(data, uriMediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("create data URI: %w", err)
	}

	return anchorURI, NewReference(dataURI, contentType), nil
}

// Anchor returns the URI of the anchor, which is a hashlink of the uncompressed/unencoded
// Original content.
func (l *AnchorLinkWithReplies) Anchor() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Anchor.URL()
}

// Original returns the contents of the anchor that was published as a data URI.
func (l *AnchorLinkWithReplies) Original() *Reference {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Original
}

// Replies returns a collection of replies to the original resource. (For example, verifiable credentials.)
func (l *AnchorLinkWithReplies) Replies() []*Reference {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Replies
}

// Profile returns the profile used to generate the link.
func (l *AnchorLinkWithReplies) Profile() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Profile.URL()
}

// Validate validates the link.
func (l *AnchorLinkWithReplies) Validate() error {
	if l == nil || l.link == nil {
		return errors.New("nil link")
	}

	anchorHL := l.Anchor()
	if anchorHL == nil {
		return errors.New("anchor URI is required")
	}

	if anchorHL.Scheme != "hl" {
		return fmt.Errorf("anchor URI is not a valid hashlink: %s", anchorHL)
	}

	if l.Profile() == nil {
		return errors.New("profile URI is required")
	}

	content, err := l.Original().Content()
	if err != nil {
		return fmt.Errorf("invalid original content: %w", err)
	}

	hashOfOriginal, err := hashlink.New().CreateResourceHash(content)
	if err != nil {
		return fmt.Errorf("create hashlink from original content: %w", err)
	}

	if hashOfOriginal != anchorHL.Opaque {
		return errors.New("hash of the original content does not match the anchor hash")
	}

	return nil
}

// MarshalJSON marshals the object to JSON.
func (l *AnchorLinkWithReplies) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.link)
}

// UnmarshalJSON umarshals the object from JSON.
func (l *AnchorLinkWithReplies) UnmarshalJSON(b []byte) error {
	l.link = &anchorLinkWithReplies{}

	return json.Unmarshal(b, l.link)
}

// Reference contains a URI and the content type of the data at that URI.
type Reference struct {
	ref *reference
}

type reference struct {
	HRef *vocab.URLProperty `json:"href"`
	Type string             `json:"type"`
}

// NewReference returns a new reference.
func NewReference(ref *url.URL, hrefType string) *Reference {
	return &Reference{
		&reference{
			HRef: vocab.NewURLProperty(ref),
			Type: hrefType,
		},
	}
}

// HRef returns the reference.
func (r *Reference) HRef() *url.URL {
	if r == nil {
		return nil
	}

	return r.ref.HRef.URL()
}

// Type returns the content-type of the reference.
func (r *Reference) Type() string {
	if r == nil {
		return ""
	}

	return r.ref.Type
}

// Content returns the decoded content of a data URI reference. If the reference
// is not a data URI then an error is returned.
func (r *Reference) Content() ([]byte, error) {
	switch {
	case strings.HasPrefix(r.HRef().String(), "data:"):
		return DecodeDataURI(r.HRef())
	default:
		return nil, fmt.Errorf("unsupported protocol for %s", r.HRef())
	}
}

// MarshalJSON marshals the object to JSON.
func (r *Reference) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ref)
}

// UnmarshalJSON umarshals the object from JSON.
func (r *Reference) UnmarshalJSON(b []byte) error {
	r.ref = &reference{}

	return json.Unmarshal(b, r.ref)
}

// Item contains a DID (in the HRef) and the previous anchor of the DID.
type Item struct {
	item *item
}

type item struct {
	HRef     *vocab.URLProperty `json:"href"`
	Previous *vocab.URLProperty `json:"previous,omitempty"`
}

// NewItem returns a new Item.
func NewItem(href, previous *url.URL) *Item {
	return &Item{
		item: &item{
			HRef:     vocab.NewURLProperty(href),
			Previous: vocab.NewURLProperty(previous),
		},
	}
}

// HRef returns the DID (as a URI).
func (i *Item) HRef() *url.URL {
	if i == nil {
		return nil
	}

	return i.item.HRef.URL()
}

// Previous returns the previous anchor or nil (for create operations).
func (i *Item) Previous() *url.URL {
	if i == nil {
		return nil
	}

	return i.item.Previous.URL()
}

// MarshalJSON marshals the object to JSON.
func (i *Item) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.item)
}

// UnmarshalJSON umarshals the object from JSON.
func (i *Item) UnmarshalJSON(b []byte) error {
	i.item = &item{}

	return json.Unmarshal(b, i.item)
}

type urlCollectionProperty struct {
	urls []*vocab.URLProperty
}

func newURLCollectionProperty(urls ...*url.URL) *urlCollectionProperty {
	if len(urls) == 0 {
		return nil
	}

	p := &urlCollectionProperty{}

	for _, u := range urls {
		p.urls = append(p.urls, vocab.NewURLProperty(u))
	}

	return p
}

func (p *urlCollectionProperty) URLs() []*url.URL {
	if p == nil || len(p.urls) == 0 {
		return nil
	}

	urls := make([]*url.URL, len(p.urls))

	for i, p := range p.urls {
		urls[i] = p.URL()
	}

	return urls
}

// MarshalJSON marshals the URL collection.
func (p *urlCollectionProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.urls)
}

// UnmarshalJSON unmarshals the URL collection.
func (p *urlCollectionProperty) UnmarshalJSON(bytes []byte) error {
	var iris []*vocab.URLProperty

	if err := json.Unmarshal(bytes, &iris); err != nil {
		return err
	}

	p.urls = iris

	return nil
}
