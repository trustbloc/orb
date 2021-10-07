/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

var (
	collID  = testutil.MustParseURL("https://org1.com/services/service1/inbox")
	first   = testutil.MustParseURL("https://org1.com/services/service1/inbox?page=true")
	last    = testutil.MustParseURL("https://org1.com/services/service1/inbox?page=true&end=true")
	current = testutil.MustParseURL("https://org1.com/services/service1/inbox?page=2")
	txn1    = testutil.MustParseURL("https://org1.com/transactions/txn1")
	txn2    = testutil.MustParseURL("https://org1.com/transactions/txn2")
)

func TestNewObjectProperty(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var p *ObjectProperty
		require.Nil(t, p.Type())
		require.Nil(t, p.Object())
		require.Nil(t, p.IRI())
		require.Nil(t, p.Collection())
		require.Nil(t, p.OrderedCollection())
		require.Nil(t, p.Activity())
		require.Nil(t, p.AnchorEvent())
		require.Nil(t, p.AnchorObject())
	})

	t.Run("Empty", func(t *testing.T) {
		p := NewObjectProperty()
		require.Nil(t, p.Type())
		require.Nil(t, p.Object())
		require.Nil(t, p.IRI())
		require.Nil(t, p.Collection())
		require.Nil(t, p.OrderedCollection())
		require.Nil(t, p.Activity())
	})

	t.Run("WithIRI", func(t *testing.T) {
		iri := testutil.MustParseURL("https://example.com/obj1")

		p := NewObjectProperty(WithIRI(iri))
		require.NotNil(t, p)
		require.Nil(t, p.Type())
		require.Nil(t, p.Object())
		require.Equal(t, iri, p.IRI())
	})

	t.Run("WithObject", func(t *testing.T) {
		p := NewObjectProperty(WithObject(NewObject(WithType(TypeVerifiableCredential), WithID(objectPropertyID))))
		require.NotNil(t, p)

		typeProp := p.Type()
		require.Nil(t, p.IRI())
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))
	})

	t.Run("WithCollection", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(txn1)),
			NewObjectProperty(WithIRI(txn2)),
		}

		coll := NewCollection(items,
			WithContext(ContextActivityStreams),
			WithID(collID),
			WithFirst(first), WithLast(last), WithCurrent(current))

		p := NewObjectProperty(WithCollection(coll))
		require.NotNil(t, p)

		typeProp := p.Type()
		require.Nil(t, p.IRI())
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeCollection))

		collProp := p.Collection()
		require.NotNil(t, collProp)

		collContext := collProp.Context()
		require.NotNil(t, collContext)
		require.True(t, collContext.Contains(ContextActivityStreams))
	})

	t.Run("WithOrderedCollection", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(txn1)),
			NewObjectProperty(WithIRI(txn2)),
		}

		coll := NewOrderedCollection(items,
			WithContext(ContextActivityStreams),
			WithID(collID),
			WithFirst(first), WithLast(last), WithCurrent(current))

		p := NewObjectProperty(WithOrderedCollection(coll))
		require.NotNil(t, p)

		typeProp := p.Type()
		require.Nil(t, p.IRI())
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeOrderedCollection))

		collProp := p.OrderedCollection()
		require.NotNil(t, collProp)

		collContext := collProp.Context()
		require.NotNil(t, collContext)
		require.True(t, collContext.Contains(ContextActivityStreams))
	})
}

func TestObjectProperty_MarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		p := NewObjectProperty()

		bytes, err := json.Marshal(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil object property")
		require.Empty(t, bytes)
	})

	t.Run("WithIRI", func(t *testing.T) {
		iri := testutil.MustParseURL("https://example.com/obj1")

		p := NewObjectProperty(WithIRI(iri))

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, jsonIRIObjectProperty, string(bytes))
	})

	t.Run("WithObject", func(t *testing.T) {
		p := NewObjectProperty(WithObject(
			NewObject(
				WithType(TypeVerifiableCredential),
				WithID(objectPropertyID),
				WithContext(ContextActivityAnchors),
			),
		))
		require.NotNil(t, p)

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonEmbeddedObjectProperty), string(bytes))
	})

	t.Run("WithAnchorEvent", func(t *testing.T) {
		witness, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(verifiableCred)))
		require.NoError(t, err)

		now := getStaticTime()

		p := NewObjectProperty(WithAnchorEvent(
			NewAnchorEvent(
				WithURL(anchorEventURL1),
				WithAttributedTo(service1),
				WithAnchors(anchorObjectURL1),
				WithPublishedTime(&now),
				WithParent(parentURL1, parentURL2),
				WithAttachment(NewObjectProperty(WithAnchorObject(NewAnchorObject(
					NewContentObject(generator, anchorObjectURL2,
						NewResource(resourceID1, ""),
						NewResource(resourceID2, prevAnchorURL2),
					),
					witness,
					WithURL(anchorObjectURL1),
				)))),
			),
		))
		require.NotNil(t, p)

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonAnchorEventProperty), string(bytes))
	})

	t.Run("WithCollection", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(txn1)),
			NewObjectProperty(WithIRI(txn2)),
		}

		coll := NewCollection(items,
			WithContext(ContextActivityStreams),
			WithID(collID),
			WithFirst(first), WithLast(last), WithCurrent(current))

		p := NewObjectProperty(WithCollection(coll))
		require.NotNil(t, p)

		bytes, err := canonicalizer.MarshalCanonical(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonCollectionObjectProperty), string(bytes))
	})

	t.Run("WithOrderedCollection", func(t *testing.T) {
		items := []*ObjectProperty{
			NewObjectProperty(WithIRI(txn1)),
			NewObjectProperty(WithIRI(txn2)),
		}

		coll := NewOrderedCollection(items,
			WithContext(ContextActivityStreams),
			WithID(collID),
			WithFirst(first), WithLast(last), WithCurrent(current))

		p := NewObjectProperty(WithOrderedCollection(coll))
		require.NotNil(t, p)

		bytes, err := canonicalizer.MarshalCanonical(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonOrderedCollectionObjectProperty), string(bytes))
	})
}

func TestObjectProperty_UnmarshalJSON(t *testing.T) {
	t.Run("WithIRI", func(t *testing.T) {
		iri := testutil.MustParseURL("https://example.com/obj1")

		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonIRIObjectProperty), p))

		require.Nil(t, p.Type())
		require.Nil(t, p.Object())
		require.Equal(t, iri, p.IRI())
	})

	t.Run("WithObject", func(t *testing.T) {
		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonEmbeddedObjectProperty), p))

		require.Nil(t, p.IRI())

		typeProp := p.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))

		obj := p.Object()
		require.NotNil(t, obj)

		context := obj.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextActivityAnchors))

		require.Equal(t, objectPropertyID.String(), obj.ID().String())

		typeProp = obj.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))
	})

	t.Run("WithAnchorEvent", func(t *testing.T) {
		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEventProperty), p))

		require.Nil(t, p.IRI())

		typeProp := p.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeAnchorEvent))

		anchorEvent := p.AnchorEvent()
		require.NotNil(t, anchorEvent)

		require.Equal(t, anchorObjectURL1.String(), anchorEvent.Anchors().String())

		require.Len(t, anchorEvent.Attachment(), 1)

		attachment := anchorEvent.Attachment()[0]
		require.NotNil(t, attachment)
		require.True(t, attachment.Type().Is(TypeAnchorObject))

		anchorObj := attachment.AnchorObject()
		require.NotNil(t, anchorObj)
		require.Len(t, anchorObj.URL(), 1)
		require.Equal(t, anchorObjectURL1.String(), anchorObj.URL()[0].String())
	})

	t.Run("WithCollection", func(t *testing.T) {
		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonCollectionObjectProperty), p))

		require.Nil(t, p.IRI())

		typeProp := p.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeCollection))

		coll := p.Collection()
		require.NotNil(t, coll)

		context := coll.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextActivityStreams))

		require.Equal(t, collID.String(), coll.ID().String())

		curr := coll.Current()
		require.NotNil(t, curr)
		require.Equal(t, current.String(), curr.String())

		frst := coll.First()
		require.NotNil(t, frst)
		require.Equal(t, first.String(), frst.String())

		lst := coll.Last()
		require.NotNil(t, lst)
		require.Equal(t, last.String(), lst.String())

		require.Equal(t, 2, coll.TotalItems())

		items := coll.Items()
		require.Len(t, items, 2)

		item := items[0]
		require.NotNil(t, item)
		iri := item.IRI()
		require.NotNil(t, iri)
		require.Equal(t, txn1.String(), iri.String())

		item = items[1]
		require.NotNil(t, item)
		iri = item.IRI()
		require.NotNil(t, iri)
		require.Equal(t, txn2.String(), iri.String())
	})

	t.Run("WithOrderedCollection", func(t *testing.T) {
		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonOrderedCollectionObjectProperty), p))

		require.Nil(t, p.IRI())

		typeProp := p.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeOrderedCollection))

		coll := p.OrderedCollection()
		require.NotNil(t, coll)

		context := coll.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextActivityStreams))

		require.Equal(t, collID.String(), coll.ID().String())

		curr := coll.Current()
		require.NotNil(t, curr)
		require.Equal(t, current.String(), curr.String())

		frst := coll.First()
		require.NotNil(t, frst)
		require.Equal(t, first.String(), frst.String())

		lst := coll.Last()
		require.NotNil(t, lst)
		require.Equal(t, last.String(), lst.String())

		require.Equal(t, 2, coll.TotalItems())

		items := coll.Items()
		require.Len(t, items, 2)

		item := items[0]
		require.NotNil(t, item)
		iri := item.IRI()
		require.NotNil(t, iri)
		require.Equal(t, txn1.String(), iri.String())

		item = items[1]
		require.NotNil(t, item)
		iri = item.IRI()
		require.NotNil(t, iri)
		require.Equal(t, txn2.String(), iri.String())
	})
}

var objectPropertyID = testutil.MustParseURL("https://example.com/some_obj_ID")

const (
	jsonIRIObjectProperty = `"https://example.com/obj1"`

	jsonEmbeddedObjectProperty = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "id": "https://example.com/some_obj_ID",
  "type": "VerifiableCredential"
}`
	jsonCollectionObjectProperty = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "current": "https://org1.com/services/service1/inbox?page=2",
  "first": "https://org1.com/services/service1/inbox?page=true",
  "id": "https://org1.com/services/service1/inbox",
  "items": [
    "https://org1.com/transactions/txn1",
    "https://org1.com/transactions/txn2"
  ],
  "last": "https://org1.com/services/service1/inbox?page=true&end=true",
  "totalItems": 2,
  "type": "Collection"
}`
	jsonOrderedCollectionObjectProperty = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "current": "https://org1.com/services/service1/inbox?page=2",
  "first": "https://org1.com/services/service1/inbox?page=true",
  "id": "https://org1.com/services/service1/inbox",
  "last": "https://org1.com/services/service1/inbox?page=true&end=true",
  "orderedItems": [
    "https://org1.com/transactions/txn1",
    "https://org1.com/transactions/txn2"
  ],
  "totalItems": 2,
  "type": "OrderedCollection"
}`

	//nolint:lll
	jsonAnchorEventProperty = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://example.com/spec#v1",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "urn:multihash:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
            },
            {
              "id": "urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
              "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
            }
          ]
        },
        "subject": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5"
      },
      "type": "AnchorObject",
      "url": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg",
      "witness": {
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
      }
    }
  ],
  "attributedTo": "https://sally.example.com/services/orb",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "published": "2021-01-27T09:30:10Z",
  "type": "AnchorEvent",
  "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY2"
}`
)
