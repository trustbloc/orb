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
	CollectionOptions
	ActivityOptions
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

// CollectionOptions holds the options for a Collection or OrderedCollection.
type CollectionOptions struct {
	First   *url.URL
	Last    *url.URL
	Current *url.URL
}

// WithFirst sets the 'first' property on the collection or ordered collection.
func WithFirst(first *url.URL) Opt {
	return func(opts *Options) {
		opts.First = first
	}
}

// WithLast sets the 'last' property on the collection or ordered collection.
func WithLast(last *url.URL) Opt {
	return func(opts *Options) {
		opts.Last = last
	}
}

// WithCurrent sets the 'current' property on the collection or ordered collection.
func WithCurrent(current *url.URL) Opt {
	return func(opts *Options) {
		opts.Current = current
	}
}

// ObjectPropertyOptions holds options for an 'object' property.
type ObjectPropertyOptions struct {
	Iri               *url.URL
	Object            *ObjectType
	Collection        *CollectionType
	OrderedCollection *OrderedCollectionType
	Activity          *ActivityType
	AnchorCredRef     *AnchorCredentialReferenceType
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

// WithCollection sets the 'object' property to an embedded collection.
func WithCollection(coll *CollectionType) Opt {
	return func(opts *Options) {
		opts.Collection = coll
	}
}

// WithOrderedCollection sets the 'object' property to an embedded ordered collection.
func WithOrderedCollection(coll *OrderedCollectionType) Opt {
	return func(opts *Options) {
		opts.OrderedCollection = coll
	}
}

// WithActivity sets the 'object' property to an embedded activity.
func WithActivity(activity *ActivityType) Opt {
	return func(opts *Options) {
		opts.Activity = activity
	}
}

// WithAnchorCredentialReference sets the 'object' property to an embedded anchored credential reference.
func WithAnchorCredentialReference(ref *AnchorCredentialReferenceType) Opt {
	return func(opts *Options) {
		opts.AnchorCredRef = ref
	}
}

// ActivityOptions holds the options for an Activity.
type ActivityOptions struct {
	Result *ObjectProperty
	Actor  *url.URL
	Target *ObjectProperty
}

// WithActor sets the 'actor' property on the activity.
func WithActor(actor *url.URL) Opt {
	return func(opts *Options) {
		opts.Actor = actor
	}
}

// WithTarget sets the 'target' property on the activity.
func WithTarget(target *ObjectProperty) Opt {
	return func(opts *Options) {
		opts.Target = target
	}
}

// WithResult sets the 'result' property on the activity.
func WithResult(result *ObjectProperty) Opt {
	return func(opts *Options) {
		opts.Result = result
	}
}

func getContexts(options *Options, contexts ...Context) []Context {
	return append(contexts, options.Context...)
}
