/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNewOptions(t *testing.T) {
	id := testutil.MustParseURL("https://example.com/1234")

	to1 := testutil.MustParseURL("https://to1")
	to2 := testutil.MustParseURL("https://to2")

	coll := NewCollection(nil)
	oColl := NewOrderedCollection(nil)
	activity := &ActivityType{}
	obj := &ObjectType{}
	iri := testutil.MustParseURL("https://iri")
	actor := testutil.MustParseURL("https://actor")
	first := testutil.MustParseURL("https://first")
	last := testutil.MustParseURL("https://last")
	current := testutil.MustParseURL("https://current")
	partOf := testutil.MustParseURL("https://activities")
	next := testutil.MustParseURL("https://activities?page=3")
	prev := testutil.MustParseURL("https://activities?page=1")

	publishedTime := time.Now()
	startTime := time.Now()
	endTime := time.Now()

	inbox := testutil.MustParseURL("https://inbox")
	outbox := testutil.MustParseURL("https://outbox")
	followers := testutil.MustParseURL("https://followers")
	following := testutil.MustParseURL("https://following")
	witnesses := testutil.MustParseURL("https://witnesses")
	witnessing := testutil.MustParseURL("https://witnessing")
	liked := testutil.MustParseURL("https://liked")

	publicKey := NewPublicKey(
		WithID(testutil.MustParseURL("https://actor/keys/main-key")),
		WithOwner(testutil.MustParseURL("https://actor")),
		WithPublicKeyPem("pem"),
	)

	target := &ObjectProperty{
		iri: NewURLProperty(testutil.MustParseURL("https://property_iri")),
	}

	result := &ObjectProperty{
		iri: NewURLProperty(testutil.MustParseURL("https://property_result")),
	}

	anchorRef := NewAnchorReference(
		testutil.MustParseURL("https://example.com/anchor_cred_ref_id"),
		testutil.MustParseURL("https://example.com/anchor_cred_iri"),
		"cid")

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
		WithPartOf(partOf),
		WithNext(next),
		WithPrev(prev),
		WithActivity(activity),
		WithTarget(target),
		WithActor(actor),
		WithResult(result),
		WithAnchorReference(anchorRef),
		WithFollowers(followers),
		WithFollowing(following),
		WithInbox(inbox),
		WithOutbox(outbox),
		WithPublicKey(publicKey),
		WithLiked(liked),
		WithWitnesses(witnesses),
		WithWitnessing(witnessing),
		WithInReplyTo(id),
		WithAttachment(NewObject()),
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
	require.Equal(t, partOf.String(), opts.PartOf.String())
	require.Equal(t, next.String(), opts.Next.String())
	require.Equal(t, prev.String(), opts.Prev.String())

	require.Equal(t, activity, opts.Activity)
	require.Equal(t, target, opts.Target)
	require.Equal(t, actor, opts.Actor)
	require.Equal(t, result, opts.Result)

	require.Equal(t, anchorRef, opts.AnchorCredRef)

	require.Equal(t, followers.String(), opts.Followers.String())
	require.Equal(t, following.String(), opts.Following.String())
	require.Equal(t, inbox.String(), opts.Inbox.String())
	require.Equal(t, outbox.String(), opts.Outbox.String())
	require.Equal(t, publicKey, opts.PublicKey)

	require.Equal(t, liked.String(), opts.Liked.String())
	require.Equal(t, witnesses.String(), opts.Witnesses.String())
	require.Equal(t, witnessing.String(), opts.Witnessing.String())
}
