/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkset

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/datauri"
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

type link struct {
	Anchor   *vocab.URLProperty `json:"anchor"`
	Profile  *vocab.URLProperty `json:"profile"`
	Author   *vocab.URLProperty `json:"author,omitempty"`
	Item     []*Item            `json:"item,omitempty"`
	Original []*Reference       `json:"original,omitempty"`
	Related  []*Reference       `json:"related,omitempty"`
	Replies  []*Reference       `json:"replies,omitempty"`
	Up       []*Reference       `json:"up,omitempty"`
	Via      []*Reference       `json:"via,omitempty"`
}

// Link is part of a Linkset.
type Link struct {
	link *link
}

// Anchor returns the anchor URI.
func (l *Link) Anchor() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Anchor.URL()
}

// Author returns the originator of the anchor.
func (l *Link) Author() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Author.URL()
}

// Items returns the items contained within the link.
func (l *Link) Items() []*Item {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Item
}

// Profile returns the profile used to generate the link.
func (l *Link) Profile() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return l.link.Profile.URL()
}

// Via returns the "via" relationship.
func (l *Link) Via() *url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	if len(l.link.Via) == 0 {
		return nil
	}

	return l.link.Via[0].HRef()
}

// Up returns a set of parents.
func (l *Link) Up() []*url.URL {
	if l == nil || l.link == nil {
		return nil
	}

	return urisFromRefs(l.link.Up)
}

func urisFromRefs(refs []*Reference) []*url.URL {
	var uris []*url.URL

	for _, ref := range refs {
		uris = append(uris, ref.HRef())
	}

	return uris
}

// Replies returns a collection of replies to the original resource. (For example, verifiable credentials.)
func (l *Link) Replies() *Reference {
	if l == nil || l.link == nil {
		return nil
	}

	if len(l.link.Replies) == 0 {
		return nil
	}

	return l.link.Replies[0]
}

// Original returns the original reference.
func (l *Link) Original() *Reference {
	if l == nil || l.link == nil {
		return nil
	}

	if len(l.link.Original) == 0 {
		return nil
	}

	return l.link.Original[0]
}

// Related returns the related reference.
func (l *Link) Related() *Reference {
	if l == nil || l.link == nil {
		return nil
	}

	if len(l.link.Related) == 0 {
		return nil
	}

	return l.link.Related[0]
}

// Validate validates the link.
func (l *Link) Validate() error {
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

	if l.Author() == nil {
		return errors.New("author URI is required")
	}

	if l.Profile() == nil {
		return errors.New("profile URI is required")
	}

	if err := validateOriginal(l.link.Original, anchorHL); err != nil {
		return err
	}

	if err := validateRelated(l.link.Related); err != nil {
		return err
	}

	return validateReplies(l.link.Related)
}

// MarshalJSON marshals the object to JSON.
func (l *Link) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.link)
}

// UnmarshalJSON umarshals the object from JSON.
func (l *Link) UnmarshalJSON(b []byte) error {
	l.link = &link{}

	return json.Unmarshal(b, l.link)
}

// Linkset contains one or more Links.
type Linkset struct {
	Linkset []*Link `json:"linkset"`
}

// New returns a new Linkset.
func New(linkset ...*Link) *Linkset {
	return &Linkset{
		Linkset: linkset,
	}
}

// Link returns the first link in the Linkset or nil if the Linkset is empty.
func (ls *Linkset) Link() *Link {
	if len(ls.Linkset) == 0 {
		return nil
	}

	return ls.Linkset[0]
}

// NewLink returns a new Link.
func NewLink(anchor, author, profile *url.URL, original, related, replies *Reference) *Link {
	return &Link{
		link: &link{
			Anchor:   vocab.NewURLProperty(anchor),
			Author:   vocab.NewURLProperty(author),
			Profile:  vocab.NewURLProperty(profile),
			Original: newRefs(original),
			Replies:  newRefs(replies),
			Related:  newRefs(related),
		},
	}
}

// NewAnchorLink returns a new anchor Link.
func NewAnchorLink(anchor, author, profile *url.URL, item []*Item) *Link {
	return &Link{
		link: &link{
			Anchor:  vocab.NewURLProperty(anchor),
			Author:  vocab.NewURLProperty(author),
			Item:    item,
			Profile: vocab.NewURLProperty(profile),
		},
	}
}

// NewRelatedLink returns a new related Link.
func NewRelatedLink(anchor, profile, via *url.URL, up ...*url.URL) *Link {
	return &Link{
		link: &link{
			Anchor:  vocab.NewURLProperty(anchor),
			Profile: vocab.NewURLProperty(profile),
			Via:     newRefsFromURIs(via),
			Up:      newRefsFromURIs(up...),
		},
	}
}

// NewAnchorRef creates a data URI Reference of the given content type and returns the anchor URI
// (which is a hashlink of the data).
func NewAnchorRef(data []byte, uriMediaType datauri.MediaType, contentType LinkType) (*url.URL, *Reference, error) {
	anchorHL, err := hashlink.New().CreateHashLink(data, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create hashlink of data: %w", err)
	}

	anchorURI, err := url.Parse(anchorHL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse anchorURI hashlink: %w", err)
	}

	dataURI, err := datauri.New(data, uriMediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("create data URI: %w", err)
	}

	return anchorURI, NewReference(dataURI, contentType), nil
}

// Reference contains a URI and the content type of the data at that URI.
type Reference struct {
	ref *reference
}

type reference struct {
	HRef *vocab.URLProperty `json:"href"`
	Type string             `json:"type,omitempty"`
}

// NewReference returns a new reference.
func NewReference(u *url.URL, hrefType string) *Reference {
	return &Reference{
		&reference{
			HRef: vocab.NewURLProperty(u),
			Type: hrefType,
		},
	}
}

func newRefs(ref *Reference) []*Reference {
	if ref == nil {
		return nil
	}

	return []*Reference{ref}
}

func newRefsFromURIs(uris ...*url.URL) []*Reference {
	var refs []*Reference

	for _, u := range uris {
		refs = append(refs, NewReference(u, ""))
	}

	return refs
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
	if r == nil {
		return nil, nil
	}

	switch {
	case strings.HasPrefix(r.HRef().String(), "data:"):
		return datauri.Decode(r.HRef())
	default:
		return nil, fmt.Errorf("unsupported protocol for %s", r.HRef())
	}
}

// Linkset decodes the data URI in href and unmarshals and returns the Linkset. If the reference
// is not a data URI or the type is not application/linkset+json then an error is returned.
func (r *Reference) Linkset() (*Linkset, error) {
	if r == nil {
		return nil, nil
	}

	if r.Type() != TypeLinkset {
		return nil, fmt.Errorf("the type of the reference should be %s but is %s",
			TypeLinkset, r.Type())
	}

	contentBytes, err := r.Content()
	if err != nil {
		return nil, fmt.Errorf("invalid Linkset content: %w", err)
	}

	ls := &Linkset{}

	err = json.Unmarshal(contentBytes, ls)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Linkset: %w", err)
	}

	return ls, nil
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
	HRef     *vocab.URLProperty     `json:"href"`
	Previous *urlCollectionProperty `json:"previous,omitempty"`
}

// NewItem returns a new Item.
func NewItem(href, previous *url.URL) *Item {
	return &Item{
		item: &item{
			HRef:     vocab.NewURLProperty(href),
			Previous: newURLCollectionProperty(previous),
		},
	}
}

// HRef returns the DID (as a URI).
func (i *Item) HRef() *url.URL {
	if i == nil || i.item == nil {
		return nil
	}

	return i.item.HRef.URL()
}

// Previous returns the previous anchor or nil (for create operations).
func (i *Item) Previous() *url.URL {
	if i == nil || i.item == nil {
		return nil
	}

	urls := i.item.Previous.URLs()

	if len(urls) == 0 {
		return nil
	}

	return urls[0]
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

func validateOriginal(original []*Reference, anchorHL *url.URL) error {
	if len(original) == 0 {
		return nil
	}

	content, err := original[0].Content()
	if err != nil {
		return fmt.Errorf("invalid 'original' content: %w", err)
	}

	hashOfOriginal, err := hashlink.New().CreateResourceHash(content)
	if err != nil {
		return fmt.Errorf("create hashlink from 'original' content: %w", err)
	}

	if hashOfOriginal != anchorHL.Opaque {
		return fmt.Errorf("hash [%s] of the 'original' content does not match the anchor hash [%s]",
			hashOfOriginal, anchorHL.Opaque)
	}

	return nil
}

func validateRelated(related []*Reference) error {
	if len(related) == 0 {
		return nil
	}

	if _, err := related[0].Content(); err != nil {
		return fmt.Errorf("invalid 'related' content: %w", err)
	}

	return nil
}

func validateReplies(replies []*Reference) error {
	if len(replies) == 0 {
		return nil
	}

	if _, err := replies[0].Content(); err != nil {
		return fmt.Errorf("invalid 'replies' content: %w", err)
	}

	return nil
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
		if u != nil {
			p.urls = append(p.urls, vocab.NewURLProperty(u))
		}
	}

	if len(p.urls) == 0 {
		return nil
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

func (p *urlCollectionProperty) MarshalJSON() ([]byte, error) {
	if len(p.urls) == 0 {
		return nil, nil
	}

	return json.Marshal(p.urls)
}

func (p *urlCollectionProperty) UnmarshalJSON(bytes []byte) error {
	var iris []*vocab.URLProperty

	if err := json.Unmarshal(bytes, &iris); err != nil {
		return err
	}

	p.urls = iris

	return nil
}
