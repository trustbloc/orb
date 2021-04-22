/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"net/url"
)

// URLProperty holds a URL.
type URLProperty struct {
	u *url.URL
}

// NewURLProperty returns a new URL property with the given URL. Nil is returned if the provided URL is nil.
func NewURLProperty(u *url.URL) *URLProperty {
	if u == nil {
		return nil
	}

	return &URLProperty{u: u}
}

// String returns the string representation of the URL.
func (p *URLProperty) String() string {
	if p == nil || p.u == nil {
		return ""
	}

	return p.u.String()
}

// URL returns the contained URL.
func (p *URLProperty) URL() *url.URL {
	if p == nil {
		return nil
	}

	return p.u
}

// MarshalJSON marshals the URL property.
func (p *URLProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.u.String()) // nolint: wrapcheck
}

// UnmarshalJSON unmarshals the URL property.
func (p *URLProperty) UnmarshalJSON(bytes []byte) error {
	var iri string

	err := json.Unmarshal(bytes, &iri)
	if err != nil {
		return err // nolint: wrapcheck
	}

	u, err := url.Parse(iri)
	if err != nil {
		return err // nolint: wrapcheck
	}

	p.u = u

	return nil
}

// URLCollectionProperty contains a collection of URLs.
type URLCollectionProperty struct {
	urls []*URLProperty
}

// NewURLCollectionProperty returns a new URL collection property. Nil is returned if no URLs were provided.
func NewURLCollectionProperty(urls ...*url.URL) *URLCollectionProperty {
	if len(urls) == 0 {
		return nil
	}

	p := &URLCollectionProperty{}

	for _, u := range urls {
		p.urls = append(p.urls, &URLProperty{u: u})
	}

	return p
}

// URLs returns the URLs.
func (p *URLCollectionProperty) URLs() []*url.URL {
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
func (p *URLCollectionProperty) MarshalJSON() ([]byte, error) {
	if len(p.urls) == 1 {
		return json.Marshal(p.urls[0]) // nolint: wrapcheck
	}

	return json.Marshal(p.urls) // nolint: wrapcheck
}

// UnmarshalJSON unmarshals the URL collection.
func (p *URLCollectionProperty) UnmarshalJSON(bytes []byte) error {
	iri := &URLProperty{}

	err := json.Unmarshal(bytes, &iri)
	if err == nil {
		p.urls = []*URLProperty{iri}

		return nil
	}

	var iris []*URLProperty

	err = json.Unmarshal(bytes, &iris)
	if err != nil {
		return err // nolint: wrapcheck
	}

	p.urls = iris

	return nil
}
