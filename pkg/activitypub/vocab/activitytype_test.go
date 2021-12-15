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

	public           = testutil.MustParseURL("https://www.w3.org/ns/activitystreams#Public")
	anchorObjectURL1 = testutil.MustParseURL("hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg")

	anchorEventURL1 = testutil.MustParseURL("hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY2") //nolint:lll

	parentURL1 = testutil.MustParseURL("hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5") //nolint:lll
	parentURL2 = testutil.MustParseURL("hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp") //nolint:lll

	attributedToURL = testutil.MustParseURL("ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p")
)

func TestCreateTypeMarshal(t *testing.T) {
	followers := newMockID(service1, "/followers")

	published := getStaticTime()

	t.Run("Marshal", func(t *testing.T) {
		vc, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(verifiableCred)))
		require.NoError(t, err)

		// Verifiable credential
		vcAnchorObj, err := NewAnchorObject(
			sampleGenerator,
			MustMarshalToDoc(vc),
		)
		require.NoError(t, err)
		require.Len(t, vcAnchorObj.URL(), 1)

		// Index
		indexAnchorObj, err := NewAnchorObject(
			sampleGenerator,
			MustMarshalToDoc(&sampleContentObj{Field1: "value1", Field2: "value2"}),
			WithLink(NewLink(vcAnchorObj.URL()[0], RelationshipWitness)),
		)
		require.NoError(t, err)
		require.Len(t, indexAnchorObj.URL(), 1)

		anchorEvent := NewAnchorEvent(
			WithURL(anchorEventURL1),
			WithAttributedTo(attributedToURL),
			WithIndex(indexAnchorObj.URL()[0]),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(indexAnchorObj))),
			WithAttachment(NewObjectProperty(WithAnchorObject(vcAnchorObj))),
		)

		create := NewCreateActivity(
			NewObjectProperty(
				WithAnchorEvent(anchorEvent),
			),
			WithID(createActivityID),
			WithActor(service1),
			WithTo(followers), WithTo(public),
			WithPublishedTime(&published),
		)

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

		objProp := a.Object()
		require.NotNil(t, objProp)

		anchorEvent := objProp.AnchorEvent()
		require.NotNil(t, anchorEvent)
		require.True(t, anchorEvent.Type().Is(TypeAnchorEvent))

		require.NotNil(t, anchorEvent)
		require.NotNil(t, anchorEvent.Index())
		require.True(t, anchorEvent.URL().Contains(anchorEventURL1))
		require.Equal(t, attributedToURL.String(), anchorEvent.AttributedTo().String())
		require.NotNil(t, anchorEvent.Published())
		require.Equal(t, published, *anchorEvent.Published())
		require.True(t, anchorEvent.Parent().Contains(parentURL1))
		require.True(t, anchorEvent.Parent().Contains(parentURL2))

		require.Len(t, anchorEvent.Attachment(), 2)

		anchorObject, err := anchorEvent.AnchorObject(anchorEvent.Index())
		require.NoError(t, err)
		require.NotNil(t, anchorObject)
		require.True(t, anchorObject.Type().Is(TypeAnchorObject))

		contentObject := anchorObject.ContentObject()
		require.NotNil(t, contentObject)
	})
}

func TestAnnounceTypeMarshal(t *testing.T) {
	followers := newMockID(service1, "/followers")

	anchorRefURL1 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbGx5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZmtyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1") //nolint:lll
	anchorRefURL2 := testutil.MustParseURL("hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5")         //nolint:lll

	t.Run("With AnchorReferences", func(t *testing.T) {
		published := getStaticTime()

		t.Run("Marshal", func(t *testing.T) {
			items := []*ObjectProperty{
				NewObjectProperty(
					WithAnchorEvent(
						NewAnchorEvent(WithURL(anchorRefURL1)),
					),
				),
				NewObjectProperty(
					WithAnchorEvent(
						NewAnchorEvent(WithURL(anchorRefURL2)),
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

			require.Equal(t, testutil.GetCanonical(t, jsonAnnounceWithRefs), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounceWithRefs), a))
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

			require.True(t, item.Type().Is(TypeAnchorEvent))
			ref := item.AnchorEvent()
			require.NotNil(t, ref)
			require.True(t, ref.URL().Contains(anchorRefURL1))

			item = items[1]

			ref = item.AnchorEvent()
			require.NotNil(t, ref)
			require.True(t, ref.URL().Contains(anchorRefURL2))
		})
	})

	t.Run("With embedded content object", func(t *testing.T) {
		published := getStaticTime()

		anchorObj, err := NewAnchorObject(
			sampleGenerator,
			MustMarshalToDoc(&sampleContentObj{Field1: "value1", Field2: "value2"}),
		)
		require.NoError(t, err)
		require.Len(t, anchorObj.URL(), 1)

		t.Run("Marshal", func(t *testing.T) {
			anchorEvent := NewAnchorEvent(
				WithURL(anchorEventURL1),
				WithAttributedTo(attributedToURL),
				WithIndex(anchorObj.URL()[0]),
				WithPublishedTime(&published),
				WithParent(parentURL1, parentURL2),
				WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
			)

			announce := NewAnnounceActivity(
				NewObjectProperty(
					WithCollection(
						NewCollection([]*ObjectProperty{
							NewObjectProperty(
								WithAnchorEvent(anchorEvent),
							),
						}),
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

			require.Equal(t, testutil.GetCanonical(t, jsonAnnounce), string(bytes))
		})

		t.Run("Unmarshal", func(t *testing.T) {
			a := &ActivityType{}
			require.NoError(t, json.Unmarshal([]byte(jsonAnnounce), a))
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

			anchorEvent := item.AnchorEvent()
			require.NotNil(t, anchorEvent)
			require.Equal(t, attributedToURL.String(), anchorEvent.AttributedTo().String())
			require.NotNil(t, anchorEvent.Published())
			require.Equal(t, published, *anchorEvent.Published())
			require.True(t, anchorEvent.Parent().Contains(parentURL1))
			require.True(t, anchorEvent.Parent().Contains(parentURL2))

			require.Len(t, anchorEvent.Attachment(), 1)

			anchorObject, err := anchorEvent.AnchorObject(anchorEvent.Index())
			require.NoError(t, err)
			require.NotNil(t, anchorObject)
			require.True(t, anchorObject.Type().Is(TypeAnchorObject))

			contentObject := anchorObject.ContentObject()
			require.NotNil(t, contentObject)
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

	obj, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(anchorEvent1)))
	require.NoError(t, err)

	offer := NewOfferActivity(
		NewObjectProperty(WithIRI(obj.URL()[0])),
		WithID(offerID),
		WithActor(org1Service),
		WithTo(org2Service),
		WithTarget(NewObjectProperty(WithIRI(AnchorWitnessTargetIRI))),
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
					WithAttachment(NewObjectProperty(WithObject(result)))),
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
		require.Equal(t, obj.URL()[0].String(), objIRI.String())

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
		anchorObj, err := NewAnchorObject(
			sampleGenerator,
			MustMarshalToDoc(&sampleContentObj{Field1: "value1", Field2: "value2"}),
		)
		require.NoError(t, err)
		require.Len(t, anchorObj.URL(), 1)

		anchorEvent := NewAnchorEvent(
			WithURL(anchorEventURL1),
			WithAttributedTo(attributedToURL),
			WithIndex(anchorObjectURL1),
			WithPublishedTime(&startTime),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		offer := NewOfferActivity(
			NewObjectProperty(
				WithAnchorEvent(anchorEvent),
			),
			WithID(offerActivityID),
			WithActor(service1),
			WithTo(to, PublicIRI),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
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

		start := a.StartTime()
		require.NotNil(t, start)
		require.Equal(t, startTime, *start)

		end := a.EndTime()
		require.NotNil(t, end)
		require.Equal(t, endTime, *end)

		objProp := a.Object()
		require.NotNil(t, objProp)

		anchorEvent := objProp.AnchorEvent()
		require.NotNil(t, anchorEvent)

		objType := anchorEvent.Type()
		require.NotNil(t, objType)
		require.True(t, objType.Is(TypeAnchorEvent))
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
			NewObjectProperty(WithAnchorEvent(NewAnchorEvent(
				WithURL(ref),
			))),
			WithID(likeActivityID),
			WithActor(actor),
			WithTo(service1, PublicIRI),
			WithPublishedTime(&publishedTime),
			WithResult(
				NewObjectProperty(WithAnchorEvent(
					NewAnchorEvent(
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

		require.True(t, a.Object().AnchorEvent().URL().Contains(ref))

		require.True(t, a.Result().AnchorEvent().URL().Contains(additionalRef1))
		require.True(t, a.Result().AnchorEvent().URL().Contains(additionalRef2))

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

//nolint:lll
const (
	jsonCreate = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "object": {
    "@context": "https://w3id.org/activityanchors/v1",
    "attachment": [
      {
        "contentObject": {
          "field_1": "value1",
          "field_2": "value2"
        },
        "generator": "https://sample.com#v0",
        "tag": [
          {
            "href": "hl:uEiB9Pl2njebAxujVKG9A65Jj1fDQiDRCiroOlnIjJzTEQw",
            "rel": [
              "witness"
            ],
            "type": "Link"
          }
        ],
        "type": "AnchorObject",
        "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA"
      },
      {
        "contentObject": {
          "@context": "https://www.w3.org/2018/credentials/v1",
          "credentialSubject": {
            "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
          },
          "issuanceDate": "2021-01-27T09:30:10Z",
          "issuer": "https://sally.example.com/services/anchor",
          "proof": [
            {
              "created": "2021-01-27T09:30:00Z",
              "domain": "sally.example.com",
              "jws": "eyJ...",
              "proofPurpose": "assertionMethod",
              "type": "JsonWebSignature2020",
              "verificationMethod": "did:example:abcd#key"
            },
            {
              "created": "2021-01-27T09:30:05Z",
              "domain": "https://witness1.example.com/ledgers/maple2021",
              "jws": "eyJ...",
              "proofPurpose": "assertionMethod",
              "type": "JsonWebSignature2020",
              "verificationMethod": "did:example:abcd#key"
            }
          ],
          "type": "VerifiableCredential"
        },
        "generator": "https://sample.com#v0",
        "type": "AnchorObject",
        "url": "hl:uEiB9Pl2njebAxujVKG9A65Jj1fDQiDRCiroOlnIjJzTEQw"
      }
    ],
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "index": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
    "parent": [
      "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
      "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
    ],
    "published": "2021-01-27T09:30:10Z",
    "type": "AnchorEvent",
    "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY2"
  },
  "published": "2021-01-27T09:30:10Z",
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
  "object": {
    "items": [
      {
        "@context": "https://w3id.org/activityanchors/v1",
        "attachment": [
          {
            "contentObject": {
              "field_1": "value1",
              "field_2": "value2"
            },
            "generator": "https://sample.com#v0",
            "type": "AnchorObject",
            "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA"
          }
        ],
        "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
        "index": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
        "parent": [
          "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
          "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
        ],
        "published": "2021-01-27T09:30:10Z",
        "type": "AnchorEvent",
        "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY2"
      }
    ],
    "totalItems": 1,
    "type": "Collection"
  },
  "published": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Announce"
}`

	//nolint:lll
	jsonAnnounceWithRefs = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "id": "https://sally.example.com/services/orb/activities/97bcd005-abb6-423d-a889-18bc1ce84988",
  "object": {
    "items": [
      {
        "@context": "https://w3id.org/activityanchors/v1",
        "type": "AnchorEvent",
        "url": "hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbGx5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZmtyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1"
      },
      {
        "@context": "https://w3id.org/activityanchors/v1",
        "type": "AnchorEvent",
        "url": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5"
      }
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

	//nolint:lll
	anchorEvent1 = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "url": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
  "attachment": [
    {
      "type": "AnchorObject",
      "url": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
      "metadata": {
        "generator": "https://example.com/spec#v1",
        "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
        "metadata": {
          "resources": [
            {
              "id": "urn:multihash:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
            },
            {
              "id": "urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
              "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
            },
            {
              "id": "urn:multihash:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
              "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
            }
          ]
        }
      },
      "witness": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiableCredential",
        "issuer": "https://sally.example.com/services/anchor",
        "issuanceDate": "2021-01-27T09:30:10Z",
        "credentialSubject": {
          "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
        },
        "proof": [
          {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "created": "2021-01-27T09:30:00Z",
            "verificationMethod": "did:example:abcd#key",
            "domain": "sally.example.com",
            "jws": "eyJ..."
          },
          {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "created": "2021-01-27T09:30:05Z",
            "verificationMethod": "did:example:abcd#key",
            "domain": "https://witness1.example.com/ledgers/maple2021",
            "jws": "eyJ..."
          }
        ]
      }
    }
  ]
}`

	//nolint:lll
	jsonLike = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://witness1.example.com/services/orb",
  "id": "https://witness1.example.com/services/orb/likes/87bcd005-abb6-433d-a889-18bc1ce84988",
  "object": {
    "@context": "https://w3id.org/activityanchors/v1",
    "type": "AnchorEvent",
    "url": "hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbGx5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZmtyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1"
  },
  "published": "2021-01-27T09:30:10Z",
  "result": {
    "@context": "https://w3id.org/activityanchors/v1",
    "type": "AnchorEvent",
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

	//nolint:lll
	jsonOffer = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://sally.example.com/services/orb",
  "endTime": "2021-01-27T09:31:10Z",
  "id": "https://sally.example.com/services/orb/activities/65b3d005-6bb6-673d-6879-18bc1ee84976",
  "object": {
    "@context": "https://w3id.org/activityanchors/v1",
    "attachment": [
      {
        "contentObject": {
          "field_1": "value1",
          "field_2": "value2"
        },
        "generator": "https://sample.com#v0",
        "type": "AnchorObject",
        "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA"
      }
    ],
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "index": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
    "parent": [
      "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
      "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
    ],
    "published": "2021-01-27T09:30:10Z",
    "type": "AnchorEvent",
    "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY2"
  },
  "startTime": "2021-01-27T09:30:10Z",
  "to": [
    "https://sally.example.com/services/orb/witnesses",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Offer"
}`

	jsonAcceptOffer = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://org2.com/services/anchor",
  "id": "https://org2.com/services/anchor/activities/ea9931ae-116c-4865-b950-a42a73e24771",
  "object": {
    "@context": "https://www.w3.org/ns/activitystreams",
    "actor": "https://org1.com/services/anchor",
    "id": "https://org1.com/services/anchor/activities/ef0f86b1-bfe7-4ccc-9400-aff4732bc1ac",
    "object": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
    "target": "https://w3id.org/activityanchors#AnchorWitness",
    "to": "https://org2.com/services/anchor",
    "type": "Offer"
  },
  "result": {
    "attachment": [
      {
        "@context": "https://www.w3.org/2018/credentials/v1",
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
    ],
    "endTime": "2021-01-27T09:31:10Z",
    "startTime": "2021-01-27T09:30:10Z",
    "type": "AnchorReceipt"
  },
  "to": [
    "https://org1.com/services/anchor",
    "https://www.w3.org/ns/activitystreams#Public"
  ],
  "type": "Accept"
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
  "@context": "https://www.w3.org/2018/credentials/v1",
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
	verifiableCred = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "type": "VerifiableCredential",
  "issuer": "https://sally.example.com/services/anchor",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
    "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
  },
  "proof": [
    {
      "type": "JsonWebSignature2020",
      "proofPurpose": "assertionMethod",
      "created": "2021-01-27T09:30:00Z",
      "verificationMethod": "did:example:abcd#key",
      "domain": "sally.example.com",
      "jws": "eyJ..."
    },
    {
      "type": "JsonWebSignature2020",
      "proofPurpose": "assertionMethod",
      "created": "2021-01-27T09:30:05Z",
      "verificationMethod": "did:example:abcd#key",
      "domain": "https://witness1.example.com/ledgers/maple2021",
      "jws": "eyJ..."
    }
  ]
}`
)
