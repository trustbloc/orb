/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	const id = "https://example.com/1234"

	to1 := mustParseURL("https://to1")
	to2 := mustParseURL("https://to2")

	obj := &ObjectType{}
	iri := mustParseURL("https://iri")
	coll := NewCollection(nil)
	oColl := NewOrderedCollection(nil)
	first := mustParseURL("https://first")
	last := mustParseURL("https://last")
	current := mustParseURL("https://current")

	publishedTime := time.Now()
	startTime := time.Now()
	endTime := time.Now()

	opts := NewOptions(
		WithID(id),
		WithContext(ContextCredentials, ContextActivityStreams),
		WithType(TypeCreate),
		WithTo(to1, to2),
		WithPublishedTime(&publishedTime),
		WithStartTime(&startTime),
		WithEndTime(&endTime),
		WithObject(obj),
		WithIRI(iri),
		WithCollection(coll),
		WithOrderedCollection(oColl),
		WithFirst(first),
		WithLast(last),
		WithCurrent(current),
	)

	require.NotNil(t, opts)

	require.Equal(t, id, opts.ID)

	require.Len(t, opts.Context, 2)
	require.Equal(t, ContextCredentials, opts.Context[0])
	require.Equal(t, ContextActivityStreams, opts.Context[1])

	require.Len(t, opts.Types, 1)
	require.Equal(t, TypeCreate, opts.Types[0])

	require.Len(t, opts.To, 2)
	require.Equal(t, to1.String(), opts.To[0].String())
	require.Equal(t, to2.String(), opts.To[1].String())

	require.Equal(t, &publishedTime, opts.Published)
	require.Equal(t, &startTime, opts.StartTime)
	require.Equal(t, &endTime, opts.EndTime)

	require.Equal(t, obj, opts.Object)

	require.Equal(t, iri.String(), opts.Iri.String())

	require.Equal(t, coll, opts.Collection)
	require.Equal(t, oColl, opts.OrderedCollection)
	require.Equal(t, first.String(), opts.First.String())
	require.Equal(t, last.String(), opts.Last.String())
	require.Equal(t, current.String(), opts.Current.String())
}
