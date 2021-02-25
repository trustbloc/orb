/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_memstore")

// Store implements an in-memory ActivityPub store.
type Store struct {
	serviceName     string
	activityStores  map[spi.ActivityStoreType]*activityStore
	referenceStores map[spi.ReferenceType]*referenceStore
	actorStore      map[string]*vocab.ActorType
	mutex           sync.RWMutex
}

// New returns a new in-memory ActivityPub store.
func New(serviceName string) *Store {
	return &Store{
		serviceName: serviceName,
		activityStores: map[spi.ActivityStoreType]*activityStore{
			spi.Inbox:  newActivitiesStore(),
			spi.Outbox: newActivitiesStore(),
		},
		referenceStores: map[spi.ReferenceType]*referenceStore{
			spi.Follower:   newReferenceStore(),
			spi.Following:  newReferenceStore(),
			spi.Witness:    newReferenceStore(),
			spi.Witnessing: newReferenceStore(),
			spi.Like:       newReferenceStore(),
			spi.Liked:      newReferenceStore(),
			spi.Share:      newReferenceStore(),
		},
		actorStore: make(map[string]*vocab.ActorType),
	}
}

// PutActor stores the given actor.
func (s *Store) PutActor(actor *vocab.ActorType) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logger.Debugf("[%s] Storing actor [%s]", s.serviceName, actor.ID())

	s.actorStore[actor.ID()] = actor

	return nil
}

// GetActor returns the actor for the given IRI. Returns an ErrNoFound error if the actor is not in the store.
func (s *Store) GetActor(iri *url.URL) (*vocab.ActorType, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	logger.Debugf("[%s] Retrieving actor [%s]", s.serviceName, iri)

	a, ok := s.actorStore[iri.String()]
	if !ok {
		return nil, spi.ErrNotFound
	}

	return a, nil
}

// AddActivity adds the given activity to the specified activity store.
func (s *Store) AddActivity(storeType spi.ActivityStoreType, activity *vocab.ActivityType) error {
	logger.Debugf("[%s] Storing activity to %s - Type: %s, ID: %s",
		s.serviceName, storeType, activity.Type(), activity.ID())

	return s.activityStores[storeType].add(activity)
}

// GetActivity returns the activity for the given ID from the given activity store
// or ErrNotFound error if it wasn't found.
func (s *Store) GetActivity(storeType spi.ActivityStoreType, activityID string) (*vocab.ActivityType, error) {
	logger.Debugf("[%s] Retrieving activity from %s - ID: %s", s.serviceName, storeType, activityID)

	return s.activityStores[storeType].get(activityID)
}

// QueryActivities queries the given activity store using the provided criteria
// and returns a results iterator.
func (s *Store) QueryActivities(storeType spi.ActivityStoreType,
	query *spi.Criteria) (spi.ActivityResultsIterator, error) {
	logger.Debugf("[%s] Querying activity from %s - Query: %+v", s.serviceName, storeType, query)

	return s.activityStores[storeType].query(query)
}

// AddReference adds the reference of the given type to the given actor.
func (s *Store) AddReference(referenceType spi.ReferenceType, actorIRI, referenceIRI *url.URL) error {
	logger.Debugf("[%s] Adding reference of type %s to actor %s: %s", s.serviceName, actorIRI, referenceIRI)

	return s.referenceStores[referenceType].add(actorIRI, referenceIRI)
}

// DeleteReference deletes the reference of the given type from the given actor.
func (s *Store) DeleteReference(referenceType spi.ReferenceType, actorIRI, referenceIRI *url.URL) error {
	logger.Debugf("[%s] Deleting reference of type %s from actor %s: %s", s.serviceName, actorIRI, referenceIRI)

	return s.referenceStores[referenceType].delete(actorIRI, referenceIRI)
}

// GetReferences returns the actor's list of references of the given type.
func (s *Store) GetReferences(referenceType spi.ReferenceType, actorIRI *url.URL) ([]*url.URL, error) {
	logger.Debugf("[%s] Retrieving references of type %s for actor %s", s.serviceName, actorIRI)

	return s.referenceStores[referenceType].get(actorIRI)
}

type activityStore struct {
	mutex      sync.RWMutex
	activities map[string]*vocab.ActivityType
}

func newActivitiesStore() *activityStore {
	return &activityStore{
		activities: make(map[string]*vocab.ActivityType),
	}
}

func (s *activityStore) add(activity *vocab.ActivityType) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.activities[activity.ID()] = activity

	return nil
}

func (s *activityStore) get(activityID string) (*vocab.ActivityType, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	a, ok := s.activities[activityID]
	if !ok {
		return nil, spi.ErrNotFound
	}

	return a, nil
}

func (s *activityStore) query(query *spi.Criteria) (spi.ActivityResultsIterator, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return newIterator(memQueryResults(s.activities).filter(query)), nil
}

type referenceStore struct {
	irisByActor map[string][]*url.URL
	mutex       sync.RWMutex
}

func newReferenceStore() *referenceStore {
	return &referenceStore{
		irisByActor: make(map[string][]*url.URL),
	}
}

func (s *referenceStore) add(actor fmt.Stringer, iri *url.URL) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	actorID := actor.String()

	s.irisByActor[actorID] = append(s.irisByActor[actorID], iri)

	return nil
}

func (s *referenceStore) delete(actor, iri fmt.Stringer) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	irisForActor := s.irisByActor[actor.String()]

	for actorIRI, i := range irisForActor {
		if i.String() == iri.String() {
			s.irisByActor[actor.String()] = append(irisForActor[0:actorIRI], irisForActor[actorIRI+1:]...)

			return nil
		}
	}

	return spi.ErrNotFound
}

func (s *referenceStore) get(actor fmt.Stringer) ([]*url.URL, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.irisByActor[actor.String()], nil
}

type queryFilter struct {
	*spi.Criteria
}

func newQueryFilter(query *spi.Criteria) *queryFilter {
	return &queryFilter{
		Criteria: query,
	}
}

func (q *queryFilter) Accept(activity *vocab.ActivityType) bool {
	if len(q.Types) > 0 {
		return activity.Type().IsAny(q.Types...)
	}

	return true
}

type memQueryResults map[string]*vocab.ActivityType

func (r memQueryResults) filter(query *spi.Criteria) []*vocab.ActivityType {
	var results []*vocab.ActivityType

	mq := newQueryFilter(query)

	for _, a := range r {
		if mq.Accept(a) {
			results = append(results, a)
		}
	}

	return results
}
