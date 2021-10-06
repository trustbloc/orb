/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// ErrNotFound is returned from various store functions when a requested
// object is not found in the store.
var ErrNotFound = fmt.Errorf("not found in ActivityPub store")

// ReferenceType defines the type of reference, e.g. follower, witness, etc.
type ReferenceType string

const (
	// Inbox indicates that the reference is an activity in a service's inbox.
	Inbox ReferenceType = "INBOX"
	// Outbox indicates that the reference is an activity in a service's outbox.
	Outbox ReferenceType = "OUTBOX"
	// PublicOutbox indicates that the reference is an activity posted to the service's outbox and was addressed
	// to 'https://www.w3.org/ns/activitystreams#Public' and therefore may be accessed by anyone without requiring
	// authentication.
	PublicOutbox ReferenceType = "PUBLIC_OUTBOX"
	// Follower indicates that the reference is an actor that's following the local service.
	Follower ReferenceType = "FOLLOWER"
	// Following indicates that the reference is an actor that the local service is following.
	Following ReferenceType = "FOLLOWING"
	// Witness indicates that the reference is an actor to which the local service sends
	// anchor credentials to witness.
	Witness ReferenceType = "WITNESS"
	// Witnessing indicates that the reference is a service from which the local service
	// receives anchor credentials to witness.
	Witnessing ReferenceType = "WITNESSING"
	// Like indicates that the reference is a 'Like' activity.
	Like ReferenceType = "LIKE"
	// Liked indicates that the reference is an object that the local service witnessed
	// and liked (endorsed).
	Liked ReferenceType = "LIKED"
	// Share indicates that the reference is an 'Announce' activity that was shared.
	Share ReferenceType = "SHARE"
	// AnchorCredential indicates that the reference is an anchor credential.
	AnchorCredential ReferenceType = "ANCHOR_CRED"
)

// Store defines the functions of an ActivityPub store.
type Store interface {
	// PutActor stores the given actor.
	PutActor(actor *vocab.ActorType) error
	// GetActor returns the actor for the given IRI. Returns an ErrNotFound error if the actor is not in the store.
	GetActor(actorIRI *url.URL) (*vocab.ActorType, error)
	// AddActivity adds the given activity to the activity store.
	AddActivity(activity *vocab.ActivityType) error
	// GetActivity returns the activity for the given ID from the given activity store
	// or an ErrNotFound error if it wasn't found.
	GetActivity(activityID *url.URL) (*vocab.ActivityType, error)
	// QueryActivities queries the given activity store using the provided criteria
	// and returns a results iterator.
	QueryActivities(query *Criteria, opts ...QueryOpt) (ActivityIterator, error)
	// AddReference adds the reference of the given type to the given object.
	AddReference(refType ReferenceType, objectIRI *url.URL, referenceIRI *url.URL, metaDataOpts ...RefMetadataOpt) error
	// DeleteReference deletes the reference of the given type from the given object.
	DeleteReference(refType ReferenceType, objectIRI *url.URL, referenceIRI *url.URL) error
	// QueryReferences returns the list of references of the given type according to the given query.
	QueryReferences(refType ReferenceType, query *Criteria, opts ...QueryOpt) (ReferenceIterator, error)
}

// SortOrder specifies the sort order of query results.
type SortOrder int

const (
	// SortAscending indicates that the query results must be sorted in ascending order.
	SortAscending SortOrder = iota
	// SortDescending indicates that the query results must be sorted in descending order.
	SortDescending
)

// QueryOptions holds options for a query.
type QueryOptions struct {
	PageNumber int
	PageSize   int
	SortOrder  SortOrder
}

// QueryOpt sets a query option.
type QueryOpt func(options *QueryOptions)

// WithPageSize sets the page size.
func WithPageSize(pageSize int) QueryOpt {
	return func(options *QueryOptions) {
		options.PageSize = pageSize
	}
}

// WithPageNum sets the page number.
func WithPageNum(pageNum int) QueryOpt {
	return func(options *QueryOptions) {
		options.PageNumber = pageNum
	}
}

// WithSortOrder sets the sort order. (Default is ascending.)
func WithSortOrder(sortOrder SortOrder) QueryOpt {
	return func(options *QueryOptions) {
		options.SortOrder = sortOrder
	}
}

// RefMetadata holds additional metadata to be stored in a reference entry.
type RefMetadata struct {
	ActivityType vocab.Type
}

// RefMetadataOpt sets additional metadata to be stored in a reference entry.
type RefMetadataOpt func(refMetaData *RefMetadata)

// WithActivityType is used to indicate that the reference points to an activity with the given type.
func WithActivityType(activityType vocab.Type) RefMetadataOpt {
	return func(refMetaData *RefMetadata) {
		refMetaData.ActivityType = activityType
	}
}

// Criteria holds the search criteria for a query.
type Criteria struct {
	Types         []vocab.Type
	ReferenceType ReferenceType
	ObjectIRI     *url.URL
	ReferenceIRI  *url.URL
	ActivityIRIs  []*url.URL
}

// CriteriaOpt sets a Criteria option.
type CriteriaOpt func(q *Criteria)

// NewCriteria returns new Criteria which may be used to perform a query.
func NewCriteria(opts ...CriteriaOpt) *Criteria {
	q := &Criteria{}

	for _, opt := range opts {
		opt(q)
	}

	return q
}

// WithType sets the object Type on the criteria.
func WithType(t ...vocab.Type) CriteriaOpt {
	return func(query *Criteria) {
		query.Types = append(query.Types, t...)
	}
}

// WithObjectIRI sets the object IRI on the criteria.
func WithObjectIRI(iri *url.URL) CriteriaOpt {
	return func(query *Criteria) {
		query.ObjectIRI = iri
	}
}

// WithReferenceType sets the reference type on the criteria.
func WithReferenceType(refType ReferenceType) CriteriaOpt {
	return func(query *Criteria) {
		query.ReferenceType = refType
	}
}

// WithReferenceIRI sets the reference IRI on the criteria.
func WithReferenceIRI(iri *url.URL) CriteriaOpt {
	return func(query *Criteria) {
		query.ReferenceIRI = iri
	}
}

// WithActivityIRIs sets the activity IRIs on the criteria.
func WithActivityIRIs(iris ...*url.URL) CriteriaOpt {
	return func(query *Criteria) {
		query.ActivityIRIs = iris
	}
}

// ActivityIterator defines the query results iterator for activity queries.
type ActivityIterator interface {
	// TotalItems returns the total number of items as a result of the query.
	TotalItems() (int, error)
	// Next returns the next activity or an ErrNotFound error if there are no more items.
	Next() (*vocab.ActivityType, error)
	// Close closes the iterator.
	Close() error
}

// ReferenceIterator defines the query results iterator for reference queries.
type ReferenceIterator interface {
	// TotalItems returns the total number of items as a result of the query.
	TotalItems() (int, error)
	// Next returns the next reference or an ErrNotFound error if there are no more items.
	Next() (*url.URL, error)
	// Close closes the iterator.
	Close() error
}
