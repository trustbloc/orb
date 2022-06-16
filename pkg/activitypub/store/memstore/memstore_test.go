/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestStore_Activity(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	var (
		serviceID1  = testutil.MustParseURL("https://example.com/services/service1")
		activityID1 = testutil.MustParseURL("https://example.com/activities/activity1")
		activityID2 = testutil.MustParseURL("https://example.com/activities/activity2")
		activityID3 = testutil.MustParseURL("https://example.com/activities/activity3")
	)

	a, err := s.GetActivity(activityID1)
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)

	activity1 := vocab.NewCreateActivity(vocab.NewObjectProperty(), vocab.WithID(activityID1))
	require.NoError(t, s.AddActivity(activity1))

	a, err = s.GetActivity(activityID1)
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, activity1, a)

	activity2 := vocab.NewAnnounceActivity(vocab.NewObjectProperty(), vocab.WithID(activityID2))
	require.NoError(t, s.AddActivity(activity2))

	activity3 := vocab.NewCreateActivity(vocab.NewObjectProperty(), vocab.WithID(activityID3))
	require.NoError(t, s.AddActivity(activity3))

	require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID1))
	require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID2))
	require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID3))

	t.Run("Query all", func(t *testing.T) {
		it, err := s.QueryActivities(spi.NewCriteria())
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID1, activityID2, activityID3)
	})

	t.Run("Query by type", func(t *testing.T) {
		it, err := s.QueryActivities(spi.NewCriteria(spi.WithType(vocab.TypeCreate)))
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID1, activityID3)
	})

	t.Run("Query by reference", func(t *testing.T) {
		it, err := s.QueryActivities(spi.NewCriteria(spi.WithReferenceType(spi.Inbox), spi.WithObjectIRI(serviceID1)))
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID1, activityID2, activityID3)
	})
}

func TestStore_Reference(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	actor1 := testutil.MustParseURL("https://actor1")
	actor2 := testutil.MustParseURL("https://actor2")
	actor3 := testutil.MustParseURL("https://actor3")

	it, err := s.QueryReferences(spi.Follower, spi.NewCriteria())
	require.EqualError(t, err, "object IRI is required")
	require.Nil(t, it)

	it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
	require.NoError(t, err)
	require.NotNil(t, it)

	checkRefQueryResults(t, it)

	require.NoError(t, s.AddReference(spi.Follower, actor1, actor2))
	require.NoError(t, s.AddReference(spi.Follower, actor1, actor3))

	it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
	require.NoError(t, err)

	checkRefQueryResults(t, it, actor2, actor3)

	it, err = s.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actor1)))
	require.NoError(t, err)

	checkRefQueryResults(t, it)

	require.NoError(t, s.AddReference(spi.Following, actor1, actor2))

	it, err = s.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actor1)))
	require.NoError(t, err)

	checkRefQueryResults(t, it, actor2)

	require.NoError(t, s.DeleteReference(spi.Follower, actor1, actor2))

	it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
	require.NoError(t, err)

	checkRefQueryResults(t, it, actor3)

	it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor2)))
	require.NoError(t, err)

	checkRefQueryResults(t, it)

	require.NoError(t, s.AddReference(spi.Follower, actor2, actor3))

	it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor2)))
	require.NoError(t, err)

	checkRefQueryResults(t, it, actor3)
}

func TestStore_ReferenceError(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	actor1 := testutil.MustParseURL("https://actor1")
	actor2 := testutil.MustParseURL("https://actor2")

	t.Run("AddReference - Nil object IRI -> error", func(t *testing.T) {
		require.EqualError(t, s.AddReference(spi.Follower, nil, actor2), "nil object IRI")
	})

	t.Run("AddReference - Nil reference -> error", func(t *testing.T) {
		require.EqualError(t, s.AddReference(spi.Follower, actor1, nil), "nil reference IRI")
	})

	t.Run("DeleteReference - Nil object IRI -> error", func(t *testing.T) {
		require.EqualError(t, s.DeleteReference(spi.Follower, nil, actor2), "nil object IRI")
	})

	t.Run("DeleteReference - Nil reference -> error", func(t *testing.T) {
		require.EqualError(t, s.DeleteReference(spi.Follower, actor1, nil), "nil reference IRI")
	})
}

func checkQueryResults(t *testing.T, it spi.ActivityIterator, expectedTypes ...*url.URL) {
	t.Helper()

	require.NotNil(t, it)

	for i := 0; i < len(expectedTypes); i++ {
		a, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.True(t, containsIRI(expectedTypes, a.ID().URL()))
	}

	a, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)
}

func checkRefQueryResults(t *testing.T, it spi.ReferenceIterator, expectedIRIs ...*url.URL) {
	t.Helper()

	require.NotNil(t, it)

	for i := 0; i < len(expectedIRIs); i++ {
		iri, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, iri)
		require.True(t, containsIRI(expectedIRIs, iri))
	}

	iri, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, iri)
}

func TestActivityQueryResults(t *testing.T) {
	createActivities := newMockActivities(vocab.TypeCreate, 7)
	announceActivities := newMockActivities(vocab.TypeAnnounce, 3)

	results := activityQueryResults(append(createActivities, announceActivities...))

	// No paging
	filtered, totalItems := results.filter(spi.NewCriteria())
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)
	require.True(t, filtered[0] == results[0])
	require.True(t, filtered[9] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(1),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 6)
	require.True(t, filtered[0] == results[4])
	require.True(t, filtered[5] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(2),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 2)
	require.True(t, filtered[0] == results[8])
	require.True(t, filtered[1] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(3),
	)
	require.Equal(t, 10, totalItems)
	require.Empty(t, filtered)

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(1),
		spi.WithSortOrder(spi.SortDescending),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 6)
	require.True(t, filtered[0] == results[5])
	require.True(t, filtered[5] == results[0])

	filtered, totalItems = results.filter(spi.NewCriteria(spi.WithType(vocab.TypeAnnounce)),
		spi.WithPageSize(3),
	)
	require.Equal(t, 3, totalItems)
	require.Len(t, filtered, 3)
	require.True(t, filtered[0] == results[7])
	require.True(t, filtered[1] == results[8])
	require.True(t, filtered[2] == results[9])
}

func TestReferenceQueryResults(t *testing.T) {
	results := refQueryResults(testutil.NewMockURLs(10, func(i int) string {
		return fmt.Sprintf("https://ref_%d", i)
	}))

	// No paging
	filtered, totalItems := results.filter(spi.NewCriteria())
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)
	require.True(t, filtered[0] == results[0])
	require.True(t, filtered[9] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(2),
		spi.WithPageNum(4),
		spi.WithSortOrder(spi.SortDescending),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)
	require.Equal(t, results[9].String(), filtered[0].String())
	require.Equal(t, results[0].String(), filtered[9].String())

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(1),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 6)
	require.True(t, filtered[0] == results[4])
	require.True(t, filtered[5] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(2),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 2)
	require.True(t, filtered[0] == results[8])
	require.True(t, filtered[1] == results[9])

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(3),
	)
	require.Equal(t, 10, totalItems)
	require.Empty(t, filtered)

	filtered, totalItems = results.filter(spi.NewCriteria(),
		spi.WithPageSize(4),
		spi.WithPageNum(1),
		spi.WithSortOrder(spi.SortDescending),
	)
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 6)
	require.True(t, filtered[0] == results[5])
	require.True(t, filtered[5] == results[0])

	filtered, totalItems = results.filter(spi.NewCriteria(), spi.WithPageSize(20))
	require.Equal(t, 10, totalItems)
	require.Len(t, filtered, 10)

	filtered, totalItems = results.filter(spi.NewCriteria(spi.WithReferenceIRI(results[7])))
	require.Equal(t, 1, totalItems)
	require.True(t, filtered[0] == results[7])
}

func newMockActivities(t vocab.Type, num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		a := newMockActivity(t, testutil.MustParseURL(fmt.Sprintf("https://activity_%s_%d", t, i)))
		activities[i] = a
	}

	return activities
}

func newMockActivity(t vocab.Type, id *url.URL) *vocab.ActivityType {
	if t == vocab.TypeAnnounce {
		return vocab.NewAnnounceActivity(vocab.NewObjectProperty(vocab.WithIRI(id)), vocab.WithID(id))
	}

	return vocab.NewCreateActivity(vocab.NewObjectProperty(), vocab.WithID(id))
}
