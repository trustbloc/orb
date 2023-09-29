/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNilCollectionPage(t *testing.T) {
	var coll *CollectionPageType

	require.Nil(t, coll.PartOf())
	require.Nil(t, coll.Next())
	require.Nil(t, coll.Prev())
}

func TestNilOrderedCollectionPage(t *testing.T) {
	var coll *OrderedCollectionPageType

	require.Nil(t, coll.PartOf())
	require.Nil(t, coll.Next())
	require.Nil(t, coll.Prev())
}

func TestCollectionPageMarshal(t *testing.T) {
	collPage1 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=1")
	collPage2 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=2")
	collPage3 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=3")
	activity1 := testutil.MustParseURL("https://org1.com/activities/activity1")
	activity2 := testutil.MustParseURL("https://org1.com/activities/activity2")
	activity3 := testutil.MustParseURL("https://org1.com/activities/activity3")

	t.Run("Marshal", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(activity1)),
			NewObjectProperty(WithIRI(activity2)),
			NewObjectProperty(WithIRI(activity3)),
		}

		coll := NewCollectionPage(items,
			WithContext(ContextActivityStreams),
			WithID(collPage2),
			WithPartOf(service1Inbox),
			WithPrev(collPage1),
			WithNext(collPage3),
		)

		bytes, err := canonicalizer.MarshalCanonical(coll)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonCollectionPage), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		c := &CollectionPageType{}
		require.NoError(t, json.Unmarshal([]byte(jsonCollectionPage), c))
		require.Equal(t, collPage2.String(), c.ID().String())

		context := c.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		partOf := c.PartOf()
		require.NotNil(t, partOf)
		require.Equal(t, service1Inbox.String(), partOf.String())

		prev := c.Prev()
		require.NotNil(t, prev)
		require.Equal(t, collPage1.String(), prev.String())

		next := c.Next()
		require.NotNil(t, next)
		require.Equal(t, collPage3.String(), next.String())

		require.Equal(t, 3, c.TotalItems())

		items := c.Items()
		require.Len(t, items, 3)
	})
}

func TestOrderedCollectionPageMarshal(t *testing.T) {
	collPage1 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=1")
	collPage2 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=2")
	collPage3 := testutil.MustParseURL("https://org1.com/services/service1/inbox?page=3")
	activity1 := testutil.MustParseURL("https://org1.com/activities/activity1")
	activity2 := testutil.MustParseURL("https://org1.com/activities/activity2")
	activity3 := testutil.MustParseURL("https://org1.com/activities/activity3")

	t.Run("Marshal", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(activity1)),
			NewObjectProperty(WithIRI(activity2)),
			NewObjectProperty(WithIRI(activity3)),
		}

		coll := NewOrderedCollectionPage(items,
			WithContext(ContextActivityStreams),
			WithID(collPage2),
			WithPartOf(service1Inbox),
			WithPrev(collPage1),
			WithNext(collPage3),
		)

		bytes, err := canonicalizer.MarshalCanonical(coll)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonOrderedCollectionPage), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		c := &OrderedCollectionPageType{}
		require.NoError(t, json.Unmarshal([]byte(jsonOrderedCollectionPage), c))
		require.Equal(t, collPage2.String(), c.ID().String())

		context := c.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		partOf := c.PartOf()
		require.NotNil(t, partOf)
		require.Equal(t, service1Inbox.String(), partOf.String())

		prev := c.Prev()
		require.NotNil(t, prev)
		require.Equal(t, collPage1.String(), prev.String())

		next := c.Next()
		require.NotNil(t, next)
		require.Equal(t, collPage3.String(), next.String())

		require.Equal(t, 3, c.TotalItems())

		items := c.Items()
		require.Len(t, items, 3)
	})
}

const (
	jsonCollectionPage = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://org1.com/services/service1/inbox?page=2",
  "type": "CollectionPage",
  "partOf": "https://org1.com/services/service1/inbox",
  "prev": "https://org1.com/services/service1/inbox?page=1",
  "next": "https://org1.com/services/service1/inbox?page=3",
  "totalItems": 3,
  "items": [
    "https://org1.com/activities/activity1",
    "https://org1.com/activities/activity2",
    "https://org1.com/activities/activity3"
  ]
}`

	jsonOrderedCollectionPage = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://org1.com/services/service1/inbox?page=2",
  "type": "OrderedCollectionPage",
  "partOf": "https://org1.com/services/service1/inbox",
  "prev": "https://org1.com/services/service1/inbox?page=1",
  "next": "https://org1.com/services/service1/inbox?page=3",
  "totalItems": 3,
  "orderedItems": [
    "https://org1.com/activities/activity1",
    "https://org1.com/activities/activity2",
    "https://org1.com/activities/activity3"
  ]
}`
)
