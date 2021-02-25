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

// ActivityStoreType indicates the type of activities store, i.e. inbox, outbox.
type ActivityStoreType string

const (
	// Inbox indicates that the activity store is the inbox.
	Inbox ActivityStoreType = "INBOX"
	// Outbox indicates that the activity store is the outbox.
	Outbox ActivityStoreType = "OUTBOX"
)

// ReferenceType defines the type of reference, e.g. follower, witness, etc.
type ReferenceType string

const (
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
	// Like indicates that the reference is an object created by the local service that was
	// liked (endorsed) by a witness.
	Like ReferenceType = "LIKE"
	// Liked indicates that the reference is an object that the local service witnessed
	// and liked (endorsed).
	Liked ReferenceType = "LIKED"
	// Share indicates that the reference is an object that the local service shared with
	// (announced to) its followers.
	Share ReferenceType = "SHARE"
)

// Store defines the functions of an ActivityPub store.
type Store interface {
	// PutActor stores the given actor.
	PutActor(actor *vocab.ActorType) error
	// GetActor returns the actor for the given IRI. Returns an ErrNotFound error if the actor is not in the store.
	GetActor(actorIRI *url.URL) (*vocab.ActorType, error)
	// AddActivity adds the given activity to the specified activity store.
	AddActivity(storeType ActivityStoreType, activity *vocab.ActivityType) error
	// GetActivity returns the activity for the given ID from the given activity store
	// or an ErrNotFound error if it wasn't found.
	GetActivity(storeType ActivityStoreType, activityID string) (*vocab.ActivityType, error)
	// QueryActivities queries the given activity store using the provided criteria
	// and returns a results iterator.
	QueryActivities(storeType ActivityStoreType, query *Criteria) (ActivityResultsIterator, error)
	// AddReference adds the reference of the given type to the given actor.
	AddReference(refType ReferenceType, actorIRI *url.URL, referenceIRI *url.URL) error
	// DeleteReference deletes the reference of the given type from the given actor.
	DeleteReference(refType ReferenceType, actorIRI *url.URL, referenceIRI *url.URL) error
	// GetReferences returns the actor's list of references of the given type.
	GetReferences(refType ReferenceType, actorIRI *url.URL) ([]*url.URL, error)
}

// Criteria holds the search criteria for a query.
type Criteria struct {
	Types []vocab.Type
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

// ActivityResultsIterator defines the query results iterator for activity queries.
type ActivityResultsIterator interface {
	// Next returns the next activity or an ErrNotFound error if there are no more items.
	Next() (*vocab.ActivityType, error)
	// Close closes the iterator.
	Close()
}
