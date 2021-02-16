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
func (t *URLProperty) String() string {
	if t.u == nil {
		return ""
	}

	return t.u.String()
}

// URL returns the contained URL.
func (t *URLProperty) URL() *url.URL {
	return t.u
}

// MarshalJSON marshals the URL property.
func (t *URLProperty) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.u.String())
}

// UnmarshalJSON unmarshals the URL property.
func (t *URLProperty) UnmarshalJSON(bytes []byte) error {
	var iri string

	err := json.Unmarshal(bytes, &iri)
	if err != nil {
		return err
	}

	u, err := url.Parse(iri)
	if err != nil {
		return err
	}

	t.u = u

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
func (t *URLCollectionProperty) URLs() []*url.URL {
	urls := make([]*url.URL, len(t.urls))

	for i, p := range t.urls {
		urls[i] = p.URL()
	}

	return urls
}

// MarshalJSON marshals the URL collection.
func (t *URLCollectionProperty) MarshalJSON() ([]byte, error) {
	if len(t.urls) == 1 {
		return json.Marshal(t.urls[0])
	}

	return json.Marshal(t.urls)
}

// UnmarshalJSON unmarshals the URL collection.
func (t *URLCollectionProperty) UnmarshalJSON(bytes []byte) error {
	iri := &URLProperty{}

	err := json.Unmarshal(bytes, &iri)
	if err == nil {
		t.urls = []*URLProperty{iri}

		return err
	}

	var iris []*URLProperty

	err = json.Unmarshal(bytes, &iris)
	if err != nil {
		return err
	}

	t.urls = iris

	return nil
}
