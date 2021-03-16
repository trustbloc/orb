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
)

func TestStore_Activity(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	const (
		activityID1 = "activity1"
		activityID2 = "activity2"
		activityID3 = "activity3"
		activityID4 = "activity4"
	)

	a, err := s.GetActivity(spi.Inbox, activityID1)
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)

	activity1 := vocab.NewCreateActivity(activityID1, vocab.NewObjectProperty())
	require.NoError(t, s.AddActivity(spi.Inbox, activity1))

	a, err = s.GetActivity(spi.Inbox, activityID1)
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, activity1, a)

	activity2 := vocab.NewAnnounceActivity(activityID2, vocab.NewObjectProperty())
	require.NoError(t, s.AddActivity(spi.Inbox, activity2))

	activity3 := vocab.NewCreateActivity(activityID3, vocab.NewObjectProperty())
	require.NoError(t, s.AddActivity(spi.Inbox, activity3))

	activity4 := vocab.NewAcceptActivity(activityID4, vocab.NewObjectProperty())
	require.NoError(t, s.AddActivity(spi.Outbox, activity4))

	t.Run("Query all", func(t *testing.T) {
		it, err := s.QueryActivities(spi.Inbox, spi.NewCriteria())
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID1, activityID2, activityID3)

		it, err = s.QueryActivities(spi.Outbox, spi.NewCriteria())
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID4)
	})

	t.Run("Query by type", func(t *testing.T) {
		it, err := s.QueryActivities(spi.Inbox, spi.NewCriteria(spi.WithType(vocab.TypeCreate)))
		require.NoError(t, err)
		require.NotNil(t, it)

		checkQueryResults(t, it, activityID1, activityID3)
	})
}

func TestStore_Reference(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	actor1 := mustParseURL("https://actor1")
	actor2 := mustParseURL("https://actor2")
	actor3 := mustParseURL("https://actor3")

	followers, err := s.GetReferences(spi.Follower, actor1)
	require.NoError(t, err)
	require.Empty(t, followers)

	require.NoError(t, s.AddReference(spi.Follower, actor1, actor2))
	require.NoError(t, s.AddReference(spi.Follower, actor1, actor3))

	followers, err = s.GetReferences(spi.Follower, actor1)
	require.NoError(t, err)
	require.Len(t, followers, 2)
	require.Equal(t, actor2.String(), followers[0].String())
	require.Equal(t, actor3.String(), followers[1].String())

	following, err := s.GetReferences(spi.Following, actor1)
	require.NoError(t, err)
	require.Empty(t, following)

	require.NoError(t, s.AddReference(spi.Following, actor1, actor2))

	following, err = s.GetReferences(spi.Following, actor1)
	require.NoError(t, err)
	require.Len(t, following, 1)
	require.Equal(t, actor2.String(), following[0].String())

	require.NoError(t, s.DeleteReference(spi.Follower, actor1, actor2))

	followers, err = s.GetReferences(spi.Follower, actor1)
	require.NoError(t, err)
	require.Len(t, followers, 1)
	require.Equal(t, actor3.String(), followers[0].String())

	followers, err = s.GetReferences(spi.Follower, actor2)
	require.NoError(t, err)
	require.Empty(t, followers)

	require.NoError(t, s.AddReference(spi.Follower, actor2, actor3))
	require.EqualError(t, s.DeleteReference(spi.Follower, actor2, actor1), spi.ErrNotFound.Error())

	followers, err = s.GetReferences(spi.Follower, actor2)
	require.NoError(t, err)
	require.Len(t, followers, 1)
	require.Equal(t, actor3.String(), followers[0].String())
}

func TestStore_Actors(t *testing.T) {
	s := New("service1")
	require.NotNil(t, s)

	actor1IRI := mustParseURL("https://actor1")
	actor2IRI := mustParseURL("https://actor2")

	a, err := s.GetActor(actor1IRI)
	require.EqualError(t, err, spi.ErrNotFound.Error())
	require.Nil(t, a)

	actor1 := vocab.NewService(actor1IRI.String())
	actor2 := vocab.NewService(actor2IRI.String())

	require.NoError(t, s.PutActor(actor1))
	require.NoError(t, s.PutActor(actor2))

	a, err = s.GetActor(actor1IRI)
	require.NoError(t, err)
	require.Equal(t, actor1, a)

	a, err = s.GetActor(actor2IRI)
	require.NoError(t, err)
	require.Equal(t, actor2, a)
}

func checkQueryResults(t *testing.T, it spi.ActivityIterator, expectedTypes ...string) {
	require.NotNil(t, it)

	for i := 0; i < len(expectedTypes); i++ {
		a, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.True(t, contains(a.ID(), expectedTypes))
	}

	a, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)
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

func contains(activityType string, types []string) bool {
	for _, t := range types {
		if t == activityType {
			return true
		}
	}

	return false
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}

func newMockActivities(t vocab.Type, num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		a := newMockActivity(t, fmt.Sprintf("https://activity_%s_%d", t, i))
		activities[i] = a
	}

	return activities
}

func newMockActivity(t vocab.Type, id string) *vocab.ActivityType {
	if t == vocab.TypeAnnounce {
		return vocab.NewAnnounceActivity(id, vocab.NewObjectProperty())
	}

	return vocab.NewCreateActivity(id, vocab.NewObjectProperty())
}
