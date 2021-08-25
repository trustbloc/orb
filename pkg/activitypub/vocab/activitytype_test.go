/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

var (
	host1    = testutil.MustParseURL("https://sally.example.com")
	service1 = testutil.MustParseURL("https://sally.example.com/services/orb")
	witness1 = testutil.MustParseURL("https://witness1.example.com/services/orb")

	createActivityID  = newMockID(service1, "/activities/97bcd005-abb6-423d-a889-18bc1ce84988")
	followActivityID  = newMockID(service1, "/activities/97b3d005-abb6-422d-a889-18bc1ee84988")
	witnessActivityID = newMockID(service1, "/activities/37b3d005-abb6-422d-a889-18bc1ee84985")
	acceptActivityID  = newMockID(service1, "/activities/95b3d005-abb6-423d-a889-18bc1ee84989")
	rejectActivityID  = newMockID(service1, "/activities/75b3d005-abb6-473d-a879-18bc1ee84979")
	offerActivityID   = newMockID(service1, "/activities/65b3d005-6bb6-673d-6879-18bc1ee84976")
	undoActivityID    = newMockID(service1, "/activities/77bcd005-abb6-433d-a889-18bc1ce64981")
	likeActivityID    = newMockID(witness1, "/likes/87bcd005-abb6-433d-a889-18bc1ce84988")
)

func TestCreateTypeMarshal(t *testing.T) {
	followers := newMockID(service1, "/followers")
	public := testutil.MustParseURL("https://www.w3.org/ns/activitystreams#Public")

	published := getStaticTime()

	t.Run("Marshal", func(t *testing.T) {
		targetProperty := NewObjectProperty(WithObject(
			NewObject(
				WithID(anchorCredIRI),
				WithCID(cid),
				WithType(TypeContentAddressedStorage),
			),
		))

		obj, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		create := NewCreateActivity(
			NewObjectProperty(WithObject(obj)),
			WithTarget(targetProperty),
			WithTo(followers),
			WithTo(public),
			WithContext(ContextActivityAnchors),
			WithPublishedTime(&published),
		)

		create.SetID(createActivityID)
		create.SetActor(service1)

		bytes, err := canonicalizer.MarshalCanonical(create)
		require.NoError(t, err)

		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonCreate), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonCreate), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeCreate))

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, createActivityID.String(), id.String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		actorURI := a.Actor()
		require.NotNil(t, actorURI)
		require.Equal(t, actorURI.String(), actorURI.String())

		to := a.To()
		require.Len(t, to, 2)
		require.Equal(t, to[0].String(), followers.String())
		require.Equal(t, to[1].String(), public.String())

		targetProp := a.Target()
		require.NotNil(t, targetProp)
		require.NotNil(t, targetProp.Object())
		require.Equal(t, anchorCredIRI.String(), targetProp.Object().ID().String())
		require.Equal(t, cid, targetProp.Object().CID())
		require.True(t, targetProp.Object().Type().Is(TypeContentAddressedStorage))

		objProp := a.Object()
		require.NotNil(t, objProp)

		obj := objProp.Object()
		require.NotNil(t, obj)
		require.True(t, obj.Type().Is(TypeVerifiableCredential, TypeAnchorCredential))
	})

	t.Run("With AnchorReference", func(t *testing.T) {
		refID := newMockID(host1, "/transactions/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")

		t.Run("Marshal", func(t *testing.T) {
			create := NewCreateActivity(
				NewObjectProperty(
					WithAnchorReference(
						NewAnchorReference(refID, anchorCredIRI, cid),
					),
				),
				WithID(createActivityID),
				WithActor(service1),
				WithTo(followers),
				WithTo(public),
				WithContext(ContextActivityAnchors),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(create)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, testutil.GetCanonical(t, jsonCreateWithAnchorCredentialRef), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonCreateWithAnchorCredentialRef), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeCreate))

			id := a.ID()
			require.NotNil(t, id)
			require.Equal(t, createActivityID.String(), id.String())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams)

			actorURI := a.Actor()
			require.NotNil(t, actorURI)
			require.Equal(t, actorURI.String(), actorURI.String())

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())

			objProp := a.Object()
			require.NotNil(t, objProp)

			ref := objProp.AnchorReference()
			require.NotNil(t, ref)
			require.True(t, ref.Type().Is(TypeAnchorRef))

			refTarget := ref.Target()
			require.NotNil(t, refTarget)

			refTargetObj := refTarget.Object()
			require.NotNil(t, refTargetObj)
			require.Equal(t, anchorCredIRI.String(), refTargetObj.ID().String())
			require.Equal(t, cid, refTargetObj.CID())

			refTargetObjType := refTargetObj.Type()
			require.NotNil(t, refTargetObjType)
			require.True(t, refTargetObjType.Is(TypeContentAddressedStorage))
		})
	})

	t.Run("With embedded AnchorCredential", func(t *testing.T) {
		t.Run("Marshal", func(t *testing.T) {
			anchorCredential, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorCredential)))
			require.NoError(t, err)

			create := NewCreateActivity(
				NewObjectProperty(
					WithObject(anchorCredential),
				),
				WithID(createActivityID),
				WithTarget(
					NewObjectProperty(
						WithObject(
							NewObject(WithID(anchorCredIRI), WithCID(cid), WithType(TypeContentAddressedStorage)),
						),
					),
				),
				WithActor(service1),
				WithTo(followers),
				WithTo(public),
				WithContext(ContextActivityAnchors),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(create)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, testutil.GetCanonical(t, jsonCreateWithAnchorCredential), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonCreateWithAnchorCredential), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeCreate))

			id := a.ID()
			require.NotNil(t, id)
			require.Equal(t, createActivityID.String(), id.String())

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
			require.True(t, targetProp.Type().Is(TypeContentAddressedStorage))

			targetObj := targetProp.Object()
			require.NotNil(t, targetObj)
			require.Equal(t, anchorCredIRI.String(), targetObj.ID().String())
			require.Equal(t, cid, targetObj.CID())

			targetObjType := targetObj.Type()
			require.NotNil(t, targetObjType)
			require.True(t, targetObjType.Is(TypeContentAddressedStorage))

			objProp := a.Object()
			require.NotNil(t, objProp)

			objTypeProp := objProp.Type()
			require.NotNil(t, objTypeProp)
			require.True(t, objTypeProp.Is(TypeVerifiableCredential, TypeAnchorCredential))
		})
	})
}

func TestAnnounceTypeMarshal(t *testing.T) {
	followers := newMockID(service1, "/followers")
	public := testutil.MustParseURL("https://www.w3.org/ns/activitystreams#Public")
	txn1 := newMockID(host1, "/transactions/bafkeexwtkfyvbkdidscmqywkyls3i")

	t.Run("Single object", func(t *testing.T) {
		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			announce := NewAnnounceActivity(
				NewObjectProperty(WithIRI(txn1)),
				WithID(createActivityID),
				WithActor(service1),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, testutil.GetCanonical(t, jsonAnnounce), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounce), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))

			id := a.ID()
			require.NotNil(t, id)
			require.Equal(t, createActivityID.String(), id.String())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams)
			context.Contains(ContextActivityAnchors)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, service1.String(), a.Actor().String())

			pub := a.Published()
			require.NotNil(t, pub)
			require.True(t, pub.Equal(published))

			objProp := a.Object()
			require.NotNil(t, objProp)
			require.Equal(t, txn1, objProp.IRI())
		})
	})

	t.Run("With AnchorReferences", func(t *testing.T) {
		const (
			cid1 = "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"
			cid2 = "bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"
		)

		anchorCredIRI1 := newMockID(host1, "/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")
		refID1 := newMockID(host1, "/transactions/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")

		anchorCredIRI2 := newMockID(host1, "/cas/bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y")
		refID2 := newMockID(host1, "/transactions/bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y")

		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			items := []*ObjectProperty{
				NewObjectProperty(
					WithAnchorReference(
						NewAnchorReference(refID1, anchorCredIRI1, cid1),
					),
				),
				NewObjectProperty(
					WithAnchorReference(
						NewAnchorReference(refID2, anchorCredIRI2, cid2),
					),
				),
			}

			coll := NewCollection(items)

			announce := NewAnnounceActivity(
				NewObjectProperty(WithCollection(coll)),
				WithID(createActivityID),
				WithActor(service1),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, testutil.GetCanonical(t, jsonAnnounceWithAnchorCredRefs), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounceWithAnchorCredRefs), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))
			require.Equal(t, createActivityID.String(), a.ID().String())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams, ContextActivityAnchors)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, service1.String(), a.Actor().String())

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

			require.True(t, item.Type().Is(TypeAnchorRef))
			ref := item.AnchorReference()
			require.NotNil(t, ref)
			require.Equal(t, refID1.String(), ref.ID().String())

			refTargetProp := ref.Target()
			require.NotNil(t, refTargetProp)

			refTargetObj := refTargetProp.Object()
			require.NotNil(t, refTargetObj)
			require.Equal(t, anchorCredIRI1.String(), refTargetObj.ID().String())
			require.Equal(t, cid1, refTargetObj.CID())

			item = items[1]

			ref = item.AnchorReference()
			require.NotNil(t, ref)
			require.Equal(t, refID2.String(), ref.ID().String())

			refTargetProp = ref.Target()
			require.NotNil(t, refTargetProp)

			refTargetObj = refTargetProp.Object()
			require.NotNil(t, refTargetObj)
			require.Equal(t, anchorCredIRI2.String(), refTargetObj.ID().String())
			require.Equal(t, cid2, refTargetObj.CID())
		})
	})

	t.Run("With AnchorReference and embedded object", func(t *testing.T) {
		refID := newMockID(host1, "/transactions/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")

		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			ref, err := NewAnchorReferenceWithDocument(refID, anchorCredIRI, cid,
				MustUnmarshalToDoc([]byte(anchorCredential)),
			)
			require.NoError(t, err)

			items := []*ObjectProperty{
				NewObjectProperty(
					WithAnchorReference(ref),
				),
			}

			announce := NewAnnounceActivity(
				NewObjectProperty(
					WithCollection(
						NewCollection(items),
					),
				),
				WithID(createActivityID),
				WithActor(service1),
				WithTo(followers), WithTo(public),
				WithPublishedTime(&published),
			)

			bytes, err := canonicalizer.MarshalCanonical(announce)
			require.NoError(t, err)
			t.Log(string(bytes))

			require.Equal(t, testutil.GetCanonical(t, jsonAnnounceWithAnchorCredRefAndEmbeddedCred), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounceWithAnchorCredRefAndEmbeddedCred), a))
			require.NotNil(t, a.Type())
			require.True(t, a.Type().Is(TypeAnnounce))
			require.Equal(t, createActivityID.String(), a.ID().String())

			context := a.Context()
			require.NotNil(t, context)
			context.Contains(ContextActivityStreams, ContextActivityAnchors)

			to := a.To()
			require.Len(t, to, 2)
			require.Equal(t, to[0].String(), followers.String())
			require.Equal(t, to[1].String(), public.String())
			require.Equal(t, service1.String(), a.Actor().String())

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
			require.Len(t, items, 1)

			item := items[0]

			ref := item.AnchorReference()
			require.NotNil(t, ref)
			require.NotNil(t, refID, ref.ID())

			refTargetProp := ref.Target()
			require.NotNil(t, refTargetProp)

			refTargetObj := refTargetProp.Object()
			require.NotNil(t, refTargetObj)
			require.Equal(t, anchorCredIRI.String(), refTargetObj.ID().String())
			require.Equal(t, cid, refTargetObj.CID())

			refObjProp := ref.Object()
			require.NotNil(t, refObjProp)

			cred := refObjProp.Object()
			require.NotNil(t, cred)

			credType := cred.Type()
			require.NotNil(t, credType.Is(TypeVerifiableCredential, TypeAnchorCredential))
		})
	})
}

func TestFollowTypeMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/service1")
	org2Service := testutil.MustParseURL("https://org1.com/services/service2")

	t.Run("Marshal", func(t *testing.T) {
		follow := NewFollowActivity(
			NewObjectProperty(WithIRI(org2Service)),
			WithID(followActivityID),
			WithActor(org1Service),
			WithTo(org2Service),
		)

		bytes, err := canonicalizer.MarshalCanonical(follow)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonFollow), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonFollow), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeFollow))
		require.Equal(t, followActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), org2Service.String())

		require.Equal(t, org1Service.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.IRI())
		require.Equal(t, org2Service.String(), objProp.IRI().String())
	})
}

func TestWitnessTypeMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/service1")
	org2Service := testutil.MustParseURL("https://org1.com/services/service2")

	t.Run("Marshal", func(t *testing.T) {
		invite := NewInviteActivity(
			NewObjectProperty(WithIRI(AnchorWitnessTargetIRI)),
			WithID(witnessActivityID),
			WithActor(org1Service),
			WithTo(org2Service),
			WithTarget(NewObjectProperty(WithIRI(org2Service))),
		)

		bytes, err := canonicalizer.MarshalCanonical(invite)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonInviteWitness), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonInviteWitness), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeInvite))
		require.Equal(t, witnessActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)
		context.Contains(ContextActivityAnchors)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), org2Service.String())

		require.Equal(t, org1Service.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp.IRI())
		require.Equal(t, AnchorWitnessTargetIRI.String(), objProp.IRI().String())

		target := a.Target()
		require.NotNil(t, target.IRI())
		require.Equal(t, org2Service.String(), target.IRI().String())
	})
}

func TestAcceptTypeMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/service1")
	org2Service := testutil.MustParseURL("https://org1.com/services/service2")

	follow := NewFollowActivity(
		NewObjectProperty(WithIRI(org2Service)),
		WithID(followActivityID),
		WithTo(org2Service),
		WithActor(org1Service),
	)

	follow.object.Context = nil

	t.Run("Marshal", func(t *testing.T) {
		accept := NewAcceptActivity(
			NewObjectProperty(WithActivity(follow)),
			WithID(acceptActivityID),
			WithActor(org2Service),
			WithTo(org1Service),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonAccept), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAccept), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeAccept))
		require.Equal(t, acceptActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), org1Service.String())

		require.Equal(t, org2Service.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.Type())
		require.True(t, objProp.Type().Is(TypeFollow))

		f := objProp.Activity()
		require.NotNil(t, f)
		require.NotNil(t, f.Type())
		require.True(t, f.Type().Is(TypeFollow))
		require.Equal(t, followActivityID.String(), f.ID().String())

		fa := f.Actor()
		require.NotNil(t, fa)
		require.Equal(t, org1Service.String(), fa.String())

		fObj := f.Object()
		require.NotNil(t, fObj)
		objIRI := fObj.IRI()
		require.NotNil(t, objIRI)
		require.Equal(t, org2Service.String(), objIRI.String())

		fTo := f.To()
		require.Len(t, fTo, 1)
		require.Equal(t, fTo[0].String(), org2Service.String())
	})
}

func TestAcceptOfferMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/anchor")
	org2Service := testutil.MustParseURL("https://org2.com/services/anchor")

	acceptID := newMockID(org2Service, "/activities/ea9931ae-116c-4865-b950-a42a73e24771")
	offerID := newMockID(org1Service, "/activities/ef0f86b1-bfe7-4ccc-9400-aff4732bc1ac")

	result, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(proof)))
	require.NoError(t, err)

	startTime := getStaticTime()
	endTime := startTime.Add(1 * time.Minute)

	obj, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorCredential1)))
	require.NoError(t, err)

	offer := NewOfferActivity(
		NewObjectProperty(WithObject(obj)),
		WithID(offerID),
		WithActor(org1Service),
		WithTo(org2Service),
		WithStartTime(&startTime),
		WithEndTime(&endTime),
		WithTarget(NewObjectProperty(WithIRI(AnchorWitnessTargetIRI))),
	)

	offer = NewOfferActivity(
		NewObjectProperty(WithIRI(obj.ID().URL())),
		WithID(offer.ID().URL()),
		WithActor(offer.Actor()),
		WithTo(offer.To()...),
		WithTarget(offer.Target()),
	)

	t.Run("Marshal", func(t *testing.T) {
		accept := NewAcceptActivity(
			NewObjectProperty(WithActivity(offer)),
			WithID(acceptID),
			WithTo(offer.Actor(), PublicIRI),
			WithActor(org2Service),
			WithResult(NewObjectProperty(
				WithObject(NewObject(
					WithType(TypeAnchorReceipt),
					WithInReplyTo(obj.ID().URL()),
					WithStartTime(&startTime),
					WithEndTime(&endTime),
					WithAttachment(result)),
				),
			)),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)

		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonAcceptOffer), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAcceptOffer), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeAccept))
		require.Equal(t, acceptID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 2)
		require.Equal(t, to[0].String(), org1Service.String())
		require.Equal(t, to[1].String(), PublicIRI.String())

		require.Equal(t, org2Service.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.Type())
		require.True(t, objProp.Type().Is(TypeOffer))

		oa := objProp.Activity()
		require.NotNil(t, oa)
		require.NotNil(t, oa.Type())
		require.True(t, oa.Type().Is(TypeOffer))
		require.Equal(t, offerID.String(), oa.ID().String())

		oaActor := oa.Actor()
		require.NotNil(t, oaActor)
		require.Equal(t, org1Service.String(), oaActor.String())

		target := oa.Target()
		require.NotNil(t, target)
		require.Equal(t, AnchorWitnessTargetIRI.String(), target.IRI().String())

		oaTo := oa.To()
		require.Len(t, oaTo, 1)
		require.Equal(t, oaTo[0].String(), org2Service.String())

		oaObj := oa.Object()
		require.NotNil(t, oaObj)
		objIRI := oaObj.IRI()
		require.NotNil(t, objIRI)
		require.Equal(t, obj.ID().String(), objIRI.String())

		result := a.Result().Object()
		require.NotNil(t, result)
		require.Equal(t, obj.ID().String(), result.InReplyTo().String())
		require.Len(t, result.Attachment(), 1)
	})
}

func TestRejectTypeMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/service1")
	org2Service := testutil.MustParseURL("https://org1.com/services/service2")

	follow := NewFollowActivity(NewObjectProperty(WithIRI(org2Service)),
		WithID(followActivityID),
		WithTo(org2Service),
		WithActor(org1Service),
	)

	follow.object.Context = nil

	t.Run("Marshal", func(t *testing.T) {
		accept := NewRejectActivity(NewObjectProperty(WithActivity(follow)),
			WithID(rejectActivityID),
			WithActor(org2Service),
			WithTo(org1Service),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonReject), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonReject), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeReject))
		require.Equal(t, rejectActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), org1Service.String())

		require.Equal(t, org2Service.String(), a.Actor().String())

		objProp := a.Object()
		require.NotNil(t, objProp)
		require.NotNil(t, objProp.Type())
		require.True(t, objProp.Type().Is(TypeFollow))

		f := objProp.Activity()
		require.NotNil(t, f)
		require.NotNil(t, f.Type())
		require.True(t, f.Type().Is(TypeFollow))
		require.Equal(t, followActivityID.String(), f.ID().String())

		fa := f.Actor()
		require.NotNil(t, fa)
		require.Equal(t, org1Service.String(), fa.String())

		fObj := f.Object()
		require.NotNil(t, fObj)
		objIRI := fObj.IRI()
		require.NotNil(t, objIRI)
		require.Equal(t, org2Service.String(), objIRI.String())

		fTo := f.To()
		require.Len(t, fTo, 1)
		require.Equal(t, fTo[0].String(), org2Service.String())
	})
}

func TestOfferTypeMarshal(t *testing.T) {
	to := newMockID(service1, "/witnesses")

	startTime := getStaticTime()
	endTime := startTime.Add(1 * time.Minute)

	t.Run("Marshal", func(t *testing.T) {
		obj, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorCredential)))
		require.NoError(t, err)

		offer := NewOfferActivity(
			NewObjectProperty(WithObject(obj)),
			WithID(offerActivityID),
			WithActor(service1),
			WithTo(to, PublicIRI),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
			WithTarget(NewObjectProperty(WithIRI(AnchorWitnessTargetIRI))),
		)

		bytes, err := canonicalizer.MarshalCanonical(offer)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonOffer), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonOffer), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeOffer))
		require.Equal(t, offerActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		require.Len(t, a.To(), 2)
		require.Equal(t, a.To()[0].String(), to.String())
		require.Equal(t, a.To()[1].String(), PublicIRI.String())

		require.Equal(t, service1.String(), a.Actor().String())

		target := a.Target()
		require.NotNil(t, target)
		require.Equal(t, AnchorWitnessTargetIRI.String(), target.IRI().String())

		start := a.StartTime()
		require.NotNil(t, start)
		require.Equal(t, startTime, *start)

		end := a.EndTime()
		require.NotNil(t, end)
		require.Equal(t, endTime, *end)

		objProp := a.Object()
		require.NotNil(t, objProp)

		obj := objProp.Object()
		require.NotNil(t, obj)

		objType := obj.Type()
		require.NotNil(t, objType)
		require.True(t, objType.Is(TypeVerifiableCredential, TypeAnchorCredential))
	})
}

func TestLikeTypeMarshal(t *testing.T) {
	actor := testutil.MustParseURL("https://witness1.example.com/services/orb")
	ref := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbG" +
		"x5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZm" +
		"tyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1")
	additionalRef1 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhodHR" +
		"wczovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw")
	additionalRef2 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhoxHR" +
		"wxzovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw")

	publishedTime := getStaticTime()

	t.Run("Marshal", func(t *testing.T) {
		like := NewLikeActivity(
			NewObjectProperty(WithObject(NewObject(
				WithType(TypeAnchorRef),
				WithURL(ref),
			))),
			WithID(likeActivityID),
			WithActor(actor),
			WithTo(service1, PublicIRI),
			WithPublishedTime(&publishedTime),
			WithResult(
				NewObjectProperty(WithObject(
					NewObject(
						WithType(TypeAnchorRef),
						WithURL(additionalRef1, additionalRef2),
					),
				)),
			),
		)

		bytes, err := canonicalizer.MarshalCanonical(like)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonLike), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonLike), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeLike))
		require.Equal(t, likeActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams, ContextActivityAnchors)

		require.Len(t, a.To(), 2)
		require.Equal(t, a.To()[0].String(), service1.String())
		require.Equal(t, a.To()[1].String(), PublicIRI.String())

		require.Equal(t, actor.String(), a.Actor().String())

		published := a.Published()
		require.NotNil(t, published)
		require.Equal(t, publishedTime, *published)

		require.True(t, a.Object().AnchorReference().URL().Contains(ref))

		require.True(t, a.Result().AnchorReference().URL().Contains(additionalRef1))
		require.True(t, a.Result().AnchorReference().URL().Contains(additionalRef2))

		bytes, err := canonicalizer.MarshalCanonical(a)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonLike), string(bytes))
	})
}

func TestUndoTypeMarshal(t *testing.T) {
	org1Service := testutil.MustParseURL("https://org1.com/services/service1")
	org2Service := testutil.MustParseURL("https://org1.com/services/service2")

	t.Run("Marshal", func(t *testing.T) {
		follow := NewFollowActivity(
			NewObjectProperty(WithIRI(org2Service)),
			WithID(followActivityID),
			WithActor(org1Service),
			WithTo(org2Service),
		)

		accept := NewUndoActivity(
			NewObjectProperty(WithActivity(follow)),
			WithID(undoActivityID),
			WithActor(org1Service),
			WithTo(org2Service),
		)

		bytes, err := canonicalizer.MarshalCanonical(accept)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonUndo), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActivityType{}
		require.NoError(t, json.Unmarshal([]byte(jsonUndo), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeUndo))
		require.Equal(t, undoActivityID.String(), a.ID().String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams)

		to := a.To()
		require.Len(t, to, 1)
		require.Equal(t, to[0].String(), org2Service.String())

		require.Equal(t, org1Service.String(), a.Actor().String())

		obj := a.Object().Activity()
		require.NotNil(t, obj.ID())
		require.True(t, obj.ID().String() == followActivityID.String())
	})
}

func TestActivityType_Accessors(t *testing.T) {
	a := &ActivityType{}

	// Ensure that we don't panic when dereferencing properties of the activity.

	require.Nil(t, a.ID())
	require.Nil(t, a.Type())
	require.Nil(t, a.Object())
	require.Nil(t, a.Object().IRI())
	require.Nil(t, a.Object().Activity())
	require.Nil(t, a.Actor())
	require.Nil(t, a.Attachment())
	require.Nil(t, a.InReplyTo())
	require.Nil(t, a.Result())
	require.Nil(t, a.Target())
	require.Nil(t, a.StartTime())
	require.Nil(t, a.EndTime())
	require.Nil(t, a.To())
}

func newMockID(serviceIRI fmt.Stringer, path string) *url.URL {
	return testutil.MustParseURL(fmt.Sprintf("%s%s", serviceIRI, path))
}

const (
	jsonCreate = `{
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/activityanchors/v1"
    ],
    "actor": "https://sally.example.com/services/orb",
    "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
    "object": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/activityanchors/v1"
      ],
      "credentialSubject": {
	"operationCount": 2,
	"coreIndex": "bafkreihwsn",
        "namespace": "did:orb",
        "previousAnchors": {
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
      "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
      "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
      "type": "ContentAddressedStorage"
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
  "object": "https://sally.example.com/transactions/bafkeexwtkfyvbkdidscmqywkyls3i",
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Announce"
}`

	jsonAnnounceWithAnchorCredRefs = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "type": "Announce",
  "actor": "https://sally.example.com/services/orb",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "published": "2021-01-27T09:30:10Z",
  "object": {
    "type": "Collection",
    "totalItems": 2,
    "items": [
      {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://w3id.org/activityanchors/v1"
        ],
        "id": "https://sally.example.com/transactions/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
        "type": "AnchorReference",
        "target": {
          "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
          "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
          "type": "ContentAddressedStorage"
        }
      },
      {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://w3id.org/activityanchors/v1"
        ],
        "id": "https://sally.example.com/transactions/bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
        "type": "AnchorReference",
        "target": {
          "id": "https://sally.example.com/cas/bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
          "cid": "bafkreiatkubvbkdedscmqwnkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
          "type": "ContentAddressedStorage"
        }
      }
    ]
  }
}`

	jsonAnnounceWithAnchorCredRefAndEmbeddedCred = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "type": "Announce",
  "actor": "https://sally.example.com/services/orb",
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "object": {
    "type": "Collection",
    "totalItems": 1,
    "items": [
      {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://w3id.org/activityanchors/v1"
        ],
        "id": "https://sally.example.com/transactions/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
        "type": "AnchorReference",
        "target": {
          "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
          "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
          "type": "ContentAddressedStorage"
        },
        "object": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/activityanchors/v1"
          ],
          "id": "http://sally.example.com/transactions/bafkreihwsn",
          "type": [
            "VerifiableCredential",
            "AnchorCredential"
          ],
          "issuer": "https://sally.example.com/services/orb",
          "issuanceDate": "2021-01-27T09:30:10Z",
          "credentialSubject": {
            "operationCount": 2,
            "coreIndex": "bafkreihwsn",
            "namespace": "did:orb",
            "previousAnchors": {
              "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
              "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
            },
            "version": "1"
          },
          "proof": {}
        }
      }
    ]
  }
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
	"https://w3id.org/activityanchors/v1"
  ],
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "type": [
	"VerifiableCredential",
	"AnchorCredential"
  ],
  "issuer": "https://sally.example.com/services/orb",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
	"operationCount": 2,
	"coreIndex": "bafkreihwsn",
	"namespace": "did:orb",
	"version": "1",
	"previousAnchors": {
	  "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
	  "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
	}
  },
  "proofChain": [{}]
}`

	//nolint:lll
	jsonLike = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "actor": "https://witness1.example.com/services/orb",
  "id": "https://witness1.example.com/services/orb/likes/87bcd005-abb6-433d-a889-18bc1ce84988",
  "object": {
    "type": "AnchorReference",
    "url": "hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbGx5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZmtyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1"
  },
  "published": "2021-01-27T09:30:10Z",
  "result": {
    "type": "AnchorReference",
    "url": [
      "hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhodHRwczovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw",
      "hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhoxHRwxzovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw"
    ]
  },
  "to": [
    "https://sally.example.com/services/orb",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Like"
}`

	jsonOffer = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "endTime": "2021-01-27T09:31:10Z",
  "id": "https://sally.example.com/services/orb/activities/65b3d005-6bb6-673d-6879-18bc1ee84976",
  "object": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/activityanchors/v1"
    ],
    "credentialSubject": {
      "operationCount": 2,
      "coreIndex": "bafkreihwsn",
      "namespace": "did:orb",
      "previousAnchors": {
        "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
        "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
      },
      "version": "1"
    },
    "id": "http://sally.example.com/transactions/bafkreihwsn",
    "issuanceDate": "2021-01-27T09:30:10Z",
    "issuer": "https://sally.example.com/services/orb",
    "proof": {},
    "type": [
      "VerifiableCredential",
      "AnchorCredential"
    ]
  },
  "startTime": "2021-01-27T09:30:10Z",
  "to": ["https://sally.example.com/services/orb/witnesses","https://www.w3.org/ns/activitystreams#Public"],
  "target": "https://w3id.org/activityanchors#AnchorWitness",
  "type": "Offer"
}`

	jsonAcceptOffer = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://org2.com/services/anchor/activities/ea9931ae-116c-4865-b950-a42a73e24771",
  "type": "Accept",
  "actor": "https://org2.com/services/anchor",
  "to": [
    "https://org1.com/services/anchor",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "object": {
    "@context": "https://www.w3.org/ns/activitystreams",
    "id": "https://org1.com/services/anchor/activities/ef0f86b1-bfe7-4ccc-9400-aff4732bc1ac",
    "type": "Offer",
    "to": "https://org2.com/services/anchor",
    "actor": "https://org1.com/services/anchor",
    "object": "http://sally.example.com/transactions/bafkreihwsn",
    "target": "https://w3id.org/activityanchors#AnchorWitness"
  },
  "result": {
    "type": "AnchorReceipt",
    "inReplyTo": "http://sally.example.com/transactions/bafkreihwsn",
    "endTime": "2021-01-27T09:31:10Z",
    "startTime": "2021-01-27T09:30:10Z",
    "attachment": [
      {
        "@context": [
          "https://w3id.org/activityanchors/v1",
          "https://w3id.org/jws/v1"
        ],
        "proof": {
          "created": "2021-01-27T09:30:15Z",
          "domain": "https://witness1.example.com/ledgers/maple2021",
          "jws": "eyJ...",
          "proofPurpose": "assertionMethod",
          "type": "JsonWebSignature2020",
          "verificationMethod": "did:example:abcd#key"
        },
        "type": "AnchorProof"
      }
    ]
  }
}`

	jsonCreateWithAnchorCredentialRef = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "type": "Create",
  "actor": "https://sally.example.com/services/orb",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "published": "2021-01-27T09:30:10Z",
  "object": {
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/activityanchors/v1"
    ],
    "id": "https://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "type": "AnchorReference",
    "target": {
      "type": "ContentAddressedStorage",
      "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
      "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"
    }
  }
}`

	jsonCreateWithAnchorCredential = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "type": "Create",
  "actor": "https://sally.example.com/services/orb",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "published": "2021-01-27T09:30:10Z",
  "target": {
    "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "type": "ContentAddressedStorage"
  },
  "object": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/activityanchors/v1"
    ],
    "id": "http://sally.example.com/transactions/bafkreihwsn",
    "type": [
      "VerifiableCredential",
      "AnchorCredential"
    ],
    "issuer": "https://sally.example.com/services/orb",
    "issuanceDate": "2021-01-27T09:30:10Z",
    "credentialSubject": {
      "operationCount": 2,
      "coreIndex": "bafkreihwsn",
      "namespace": "did:orb",
      "previousAnchors": {
        "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
        "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
      },
      "version": "1"
    },
    "proof": {}
  }
}`

	jsonUndo = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://org1.com/services/service1",
  "id": "https://sally.example.com/services/orb/activities/77bcd005-abb6-433d-a889-18bc1ce64981",
  "object": {
    "@context": "https://www.w3.org/ns/activitystreams",
    "actor": "https://org1.com/services/service1",
    "id": "https://sally.example.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988",
    "object": "https://org1.com/services/service2",
    "to": "https://org1.com/services/service2",
    "type": "Follow"
  },
  "to": "https://org1.com/services/service2",
  "type": "Undo"
}`

	jsonInviteWitness = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "actor": "https://org1.com/services/service1",
  "id": "https://sally.example.com/services/orb/activities/37b3d005-abb6-422d-a889-18bc1ee84985",
  "object": "https://w3id.org/activityanchors#AnchorWitness",
  "target": "https://org1.com/services/service2",
  "to": "https://org1.com/services/service2",
  "type": "Invite"
}`

	proof = `{
  "@context": [
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/jws/v1"
  ],
  "type": "AnchorProof",
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
