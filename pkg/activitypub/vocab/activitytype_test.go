/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

const (
	createActivityID = "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988"
	followActivityID = "https://sally.example.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988"
	acceptActivityID = "https://sally.example.com/services/orb/activities/95b3d005-abb6-423d-a889-18bc1ee84989"
	rejectActivityID = "https://sally.example.com/services/orb/activities/75b3d005-abb6-473d-a879-18bc1ee84979"
	likeActivityID   = "https://witness1.example.com/services/orb/likes/87bcd005-abb6-433d-a889-18bc1ce84988"
)

func TestCreateTypeMarshal(t *testing.T) {
	actor := mustParseURL("https://sally.example.com/services/orb")
	followers := mustParseURL("https://sally.example.com/services/orb/followers")
	public := mustParseURL("https://www.w3.org/ns/activitystreams#Public")
	cid := "97bcd005-abb6-423d-a889-18bc1ce84988"

	published := getStaticTime()

	t.Run("Marshal", func(t *testing.T) {
		targetProperty := NewObjectProperty(WithObject(
			NewObject(
				WithID(cid),
				WithType(TypeCAS),
			),
		))

		obj, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		create := NewCreateActivity(createActivityID,
			NewObjectProperty(WithObject(obj)),
			WithActor(actor),
			WithTarget(targetProperty),
			WithTo(followers),
			WithTo(public),
			WithContext(ContextOrb),
			WithPublishedTime(&published),
		)

		bytes, err := canonicalizer.MarshalCanonical(create)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonCreate), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonCreate), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeCreate))

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, createActivityID, id)

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		actor := a.Actor()
		require.NotNil(t, actor)
		require.Equal(t, actor.String(), actor.String())

		to := a.To()
		require.Len(t, to, 2)
		require.Equal(t, to[0].String(), followers.String())
		require.Equal(t, to[1].String(), public.String())

		targetProp := a.Target()
		require.NotNil(t, targetProp)
		require.NotNil(t, targetProp.Object())
		require.Equal(t, cid, targetProp.Object().ID())
		require.True(t, targetProp.Object().Type().Is(TypeCAS))

		objProp := a.Object()
		require.NotNil(t, objProp)

		obj := objProp.Object()
		require.NotNil(t, obj)
		require.True(t, obj.Type().Is(TypeVerifiableCredential, TypeAnchorCredential))
	})
}

func TestAnnounceTypeMarshal(t *testing.T) {
	followers := mustParseURL("https://sally.example.com/services/orb/followers")
	public := mustParseURL("https://www.w3.org/ns/activitystreams#Public")
	actor := mustParseURL("https://sally.example.com/services/orb")
	txn1 := mustParseURL("http://sally.example.com/transactions/bafkeexwtkfyvbkdidscmqywkyls3i")
	txn2 := mustParseURL("http://sally.example.com/transactions/bafkeexatkfbvbkdidscmqywkyls3i")

	t.Run("Single object", func(t *testing.T) {
		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			announce := NewAnnounceActivity(
				createActivityID,
				NewObjectProperty(WithIRI(txn1)),
				WithActor(actor),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, getCanonical(t, jsonAnnounce), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounce), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))

			id := a.ID()
			require.NotNil(t, id)
			require.Equal(t, createActivityID, id)

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams)
			context.Contains(ContextOrb)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, actor.String(), a.Actor().String())

			pub := a.Published()
			require.NotNil(t, pub)
			require.True(t, pub.Equal(published))

			objProp := a.Object()
			require.NotNil(t, objProp)
			require.Equal(t, txn1, objProp.IRI())
		})
	})

	t.Run("With collection", func(t *testing.T) {
		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			items := []*ObjectProperty{
				NewObjectProperty(WithIRI(txn1)),
				NewObjectProperty(WithIRI(txn2)),
			}

			coll := NewCollection(items)

			announce := NewAnnounceActivity(createActivityID,
				NewObjectProperty(WithCollection(coll)),
				WithActor(actor),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, getCanonical(t, jsonAnnounceWithCollection), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounceWithCollection), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))
			require.Equal(t, createActivityID, a.ID())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams, ContextOrb)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, actor.String(), a.Actor().String())

			pub := a.Published()
			require.NotNil(t, pub)
			require.True(t, pub.Equal(published))

			objProp := a.Object()
			require.NotNil(t, objProp)
			require.NotNil(t, objProp.Type())
			require.True(t, objProp.Type().Is(TypeCollection))

			coll := objProp.Collection()
			require.NotNil(t, coll)

			items := coll.Items()
			require.Len(t, items, 2)

			item := items[0]
			require.Equal(t, txn1, item.IRI())

			item = items[1]
			require.Equal(t, txn2, item.IRI())
		})
	})

	t.Run("With embedded objects", func(t *testing.T) {
		const (
			id1 = "97bcd005-abb6-423d-a889-18bc1ce84988"
			id2 = "77dcd005-abb6-423d-a889-18bc1ce84988"
		)

		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			items := []*ObjectProperty{
				NewObjectProperty(WithObject(NewObject(WithID(id1), WithType(TypeCAS)))),
				NewObjectProperty(WithObject(NewObject(WithID(id2), WithType(TypeCAS)))),
			}

			announce := NewAnnounceActivity(createActivityID,
				NewObjectProperty(WithOrderedCollection(NewOrderedCollection(items))),
				WithActor(actor),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, getCanonical(t, jsonAnnounceWithEmbeddedObjects), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounceWithEmbeddedObjects), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))
			require.Equal(t, createActivityID, a.ID())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams, ContextOrb)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, actor.String(), a.Actor().String())

			pub := a.Published()
			require.NotNil(t, pub)
			require.True(t, pub.Equal(published))

			objProp := a.Object()
			require.NotNil(t, objProp)
			require.NotNil(t, objProp.Type())
			require.True(t, objProp.Type().Is(TypeOrderedCollection))

			coll := objProp.OrderedCollection()
			require.NotNil(t, coll)

			items := coll.Items()
			require.Len(t, items, 2)

			item := items[0]
			require.NotNil(t, item.Type())
			require.True(t, item.Type().Is(TypeCAS))

			item = items[1]
			require.NotNil(t, item.Type())
			require.True(t, item.Type().Is(TypeCAS))
		})
	})
}

func TestFollowTypeMarshal(t *testing.T) {
	service1 := mustParseURL("https://org1.com/services/service1")
	service2 := mustParseURL("https://org1.com/services/service2")

	t.Run("Marshal", func(t *testing.T) {
		follow := NewFollowActivity(followActivityID,
			NewObjectProperty(WithIRI(service2)),
			WithActor(service1),
			WithTo(service2),
		)

		bytes, err := canonicalizer.MarshalCanonical(follow)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonFollow), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonFollow), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeFollow))
		require.Equal(t, followActivityID, a.ID())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), service2.String())

		require.Equal(t, service1.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.IRI())
		require.Equal(t, service2.String(), objProp.IRI().String())
	})
}

func TestAcceptTypeMarshal(t *testing.T) {
	service1 := mustParseURL("https://org1.com/services/service1")
	service2 := mustParseURL("https://org1.com/services/service2")

	follow := NewFollowActivity(followActivityID,
		NewObjectProperty(WithIRI(service2)),
		WithTo(service2),
		WithActor(service1),
	)

	follow.object.Context = nil

	t.Run("Marshal", func(t *testing.T) {
		accept := NewAcceptActivity(acceptActivityID,
			NewObjectProperty(WithActivity(follow)),
			WithActor(service2),
			WithTo(service1),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonAccept), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAccept), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeAccept))
		require.Equal(t, acceptActivityID, a.ID())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), service1.String())

		require.Equal(t, service2.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.Type())
		require.True(t, objProp.Type().Is(TypeFollow))

		f := objProp.Activity()
		require.NotNil(t, f)
		require.NotNil(t, f.Type())
		require.True(t, f.Type().Is(TypeFollow))
		require.Equal(t, followActivityID, f.ID())

		fa := f.Actor()
		require.NotNil(t, fa)
		require.Equal(t, service1.String(), fa.String())

		fObj := f.Object()
		require.NotNil(t, fObj)
		objIRI := fObj.IRI()
		require.NotNil(t, objIRI)
		require.Equal(t, service2.String(), objIRI.String())

		fTo := f.To()
		require.Len(t, fTo, 1)
		require.Equal(t, fTo[0].String(), service2.String())
	})
}

func TestRejectTypeMarshal(t *testing.T) {
	service1 := mustParseURL("https://org1.com/services/service1")
	service2 := mustParseURL("https://org1.com/services/service2")

	follow := NewFollowActivity(followActivityID, NewObjectProperty(WithIRI(service2)),
		WithTo(service2),
		WithActor(service1),
	)

	follow.object.Context = nil

	t.Run("Marshal", func(t *testing.T) {
		accept := NewRejectActivity(rejectActivityID, NewObjectProperty(WithActivity(follow)),
			WithActor(service2),
			WithTo(service1),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonReject), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonReject), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeReject))
		require.Equal(t, rejectActivityID, a.ID())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), service1.String())

		require.Equal(t, service2.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.Type())
		require.True(t, objProp.Type().Is(TypeFollow))

		f := objProp.Activity()
		require.NotNil(t, f)
		require.NotNil(t, f.Type())
		require.True(t, f.Type().Is(TypeFollow))
		require.Equal(t, followActivityID, f.ID())

		fa := f.Actor()
		require.NotNil(t, fa)
		require.Equal(t, service1.String(), fa.String())

		fObj := f.Object()
		require.NotNil(t, fObj)
		objIRI := fObj.IRI()
		require.NotNil(t, objIRI)
		require.Equal(t, service2.String(), objIRI.String())

		fTo := f.To()
		require.Len(t, fTo, 1)
		require.Equal(t, fTo[0].String(), service2.String())
	})
}

func TestLikeTypeMarshal(t *testing.T) {
	actor := mustParseURL("https://witness1.example.com/services/orb")
	to := mustParseURL("https://sally.example.com/services/orb")
	public := mustParseURL(PublicIRI)
	credID := mustParseURL("http://sally.example.com/transactions/bafkreihwsn")

	startTime := getStaticTime()
	endTime := startTime.Add(1 * time.Minute)

	t.Run("Marshal", func(t *testing.T) {
		result, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(jsonLikeResult)))
		require.NoError(t, err)

		like := NewLikeActivity(likeActivityID,
			NewObjectProperty(WithIRI(credID)),
			WithActor(actor),
			WithTo(to, public),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
			WithResult(NewObjectProperty(WithObject(result))),
		)

		bytes, err := canonicalizer.MarshalCanonical(like)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonLike), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonLike), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeLike))
		require.Equal(t, likeActivityID, a.ID())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		require.Len(t, a.To(), 2)
		require.Equal(t, a.To()[0].String(), to.String())
		require.Equal(t, a.To()[1].String(), PublicIRI)

		require.Equal(t, actor.String(), a.Actor().String())

		start := a.StartTime()
		require.NotNil(t, start)
		require.Equal(t, startTime, *start)

		end := a.EndTime()
		require.NotNil(t, end)
		require.Equal(t, endTime, *end)

		objProp := a.Object()
		require.NotNil(t, objProp)

		iri := objProp.IRI()
		require.NotNil(t, iri)
		require.Equal(t, credID.String(), iri.String())

		resultProp := a.Result()
		require.NotNil(t, resultProp)

		result := resultProp.Object()
		require.NotNil(t, result)
		_, ok := result.Value("proof")
		require.True(t, ok)

		bytes, err := canonicalizer.MarshalCanonical(a)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonLike), string(bytes))
	})
}

const (
	jsonCreate = `{
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://trustbloc.github.io/Context/orb-v1.json"
    ],
    "actor": "https://sally.example.com/services/orb",
    "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
    "object": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://trustbloc.github.io/Context/orb-v1.json"
      ],
      "credentialSubject": {
        "anchorString": "bafkreihwsn",
        "namespace": "did:orb",
        "previousTransactions": {
          "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
          "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
        },
        "version": "1"
      },
      "id": "http://sally.example.com/transactions/bafkreihwsn",
      "issuanceDate": "2021-01-27T09:30:10Z",
      "issuer": "https://sally.example.com/services/orb",
      "proofChain": [
        {}
      ],
      "type": [
        "VerifiableCredential",
        "AnchorCredential"
      ]
    },
    "published": "2021-01-27T09:30:10Z",
    "target": {
      "id": "97bcd005-abb6-423d-a889-18bc1ce84988",
      "type": "Cas"
    },
    "to": [
      "https://sally.example.com/services/orb/followers",
      "https://www.w3.org/ns/activitystreams#Public"
    ],
    "type": "Create"
  }`

	jsonAnnounce = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "object": "http://sally.example.com/transactions/bafkeexwtkfyvbkdidscmqywkyls3i",
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Announce"
}`

	jsonAnnounceWithCollection = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "object": {
    "items": [
      "http://sally.example.com/transactions/bafkeexwtkfyvbkdidscmqywkyls3i",
      "http://sally.example.com/transactions/bafkeexatkfbvbkdidscmqywkyls3i"
    ],
    "totalItems": 2,
    "type": "Collection"
  },
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Announce"
}`

	jsonAnnounceWithEmbeddedObjects = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "object": {
    "orderedItems": [
      {
        "id": "97bcd005-abb6-423d-a889-18bc1ce84988",
        "type": "Cas"
      },
      {
        "id": "77dcd005-abb6-423d-a889-18bc1ce84988",
        "type": "Cas"
      }
    ],
    "totalItems": 2,
    "type": "OrderedCollection"
  },
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Announce"
}`

	jsonFollow = `{
	 "@context": "https://www.w3.org/ns/activitystreams",
	 "id": "https://sally.example.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988",
	 "type": "Follow",
	 "actor": "https://org1.com/services/service1",
	 "to": "https://org1.com/services/service2",
	 "object": "https://org1.com/services/service2"
	}`

	jsonAccept = `{
    "@context": "https://www.w3.org/ns/activitystreams",
    "id": "https://sally.example.com/services/orb/activities/95b3d005-abb6-423d-a889-18bc1ee84989",
    "type": "Accept",
    "actor": "https://org1.com/services/service2",
    "to": "https://org1.com/services/service1",
    "object": {
      "actor": "https://org1.com/services/service1",
      "id": "https://sally.example.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988",
      "object": "https://org1.com/services/service2",
      "to": "https://org1.com/services/service2",
      "type": "Follow"
    }
  }`

	jsonReject = `{
	"@context": "https://www.w3.org/ns/activitystreams",
	"id": "https://sally.example.com/services/orb/activities/75b3d005-abb6-473d-a879-18bc1ee84979",
	"type": "Reject",
	"actor": "https://org1.com/services/service2",
	"to": "https://org1.com/services/service1",
	"object": {
	  "actor": "https://org1.com/services/service1",
	  "id": "https://sally.example.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988",
	  "object": "https://org1.com/services/service2",
	  "to": "https://org1.com/services/service2",
	  "type": "Follow"
	}
}`

	anchorCredential1 = `{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/Context/orb-v1.json"
  ],
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "type": [
	"VerifiableCredential",
	"AnchorCredential"
  ],
  "issuer": "https://sally.example.com/services/orb",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
	"anchorString": "bafkreihwsn",
	"namespace": "did:orb",
	"version": "1",
	"previousTransactions": {
	  "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
	  "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
	}
  },
  "proofChain": [{}]
}`

	jsonLike = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://witness1.example.com/services/orb",
  "endTime": "2021-01-27T09:31:10Z",
  "id": "https://witness1.example.com/services/orb/likes/87bcd005-abb6-433d-a889-18bc1ce84988",
  "object": "http://sally.example.com/transactions/bafkreihwsn",
  "result": {
    "@context": [
      "https://w3id.org/security/v1",
      "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "proof": {
      "created": "2021-01-27T09:30:15Z",
      "domain": "https://witness1.example.com/ledgers/maple2021",
      "jws": "eyJ...",
      "proofPurpose": "assertionMethod",
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:example:abcd#key"
    }
  },
  "startTime": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Like"
}`

	jsonLikeResult = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "proof": {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:15Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "https://witness1.example.com/ledgers/maple2021",
    "jws": "eyJ..."
  }
}`
)
