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
)
