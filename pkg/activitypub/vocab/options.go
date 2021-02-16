/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
	"time"
)

// Options holds all of the options for building an ActivityPub object.
type Options struct {
	Context   []Context
	ID        string
	To        []*url.URL
	Published *time.Time
	StartTime *time.Time
	EndTime   *time.Time
	Types     []Type

	ObjectPropertyOptions
}

// Opt is an for an object, activity, etc.
type Opt func(opts *Options)

// NewOptions returns an Options struct which is populated with the provided options.
func NewOptions(opts ...Opt) *Options {
	options := &Options{}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// WithContext sets the 'context' property on the object.
func WithContext(context ...Context) Opt {
	return func(opts *Options) {
		opts.Context = context
	}
}

// WithID sets the 'id' property on the object.
func WithID(id string) Opt {
	return func(opts *Options) {
		opts.ID = id
	}
}

// WithTo sets the "to" property on the object.
func WithTo(to ...*url.URL) Opt {
	return func(opts *Options) {
		opts.To = append(opts.To, to...)
	}
}

// WithType sets tye 'type' property on the object.
func WithType(t ...Type) Opt {
	return func(opts *Options) {
		opts.Types = t
	}
}

// WithPublishedTime sets the 'publishedTime' property on the object.
func WithPublishedTime(t *time.Time) Opt {
	return func(opts *Options) {
		opts.Published = t
	}
}

// WithStartTime sets the 'startTime' property on the object.
func WithStartTime(t *time.Time) Opt {
	return func(opts *Options) {
		opts.StartTime = t
	}
}

// WithEndTime sets the 'endTime' property on the object.
func WithEndTime(t *time.Time) Opt {
	return func(opts *Options) {
		opts.EndTime = t
	}
}

// ObjectPropertyOptions holds options for an 'object' property.
type ObjectPropertyOptions struct {
	Iri    *url.URL
	Object *ObjectType
}

// WithIRI sets the 'object' property to an IRI.
func WithIRI(iri *url.URL) Opt {
	return func(opts *Options) {
		opts.Iri = iri
	}
}

// WithObject sets the 'object' property to an embedded object.
func WithObject(obj *ObjectType) Opt {
	return func(opts *Options) {
		opts.Object = obj
	}
}
