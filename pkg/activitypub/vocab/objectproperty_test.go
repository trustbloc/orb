/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewObjectProperty(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		p := NewObjectProperty()
		require.NotNil(t, p)
		require.Nil(t, p.GetType())
	})

	t.Run("WithIRI", func(t *testing.T) {
		iri := mustParseURL("https://example.com/obj1")

		p := NewObjectProperty(WithIRI(iri))
		require.NotNil(t, p)
		require.Nil(t, p.GetType())
		require.Nil(t, p.GetObject())
		require.Equal(t, iri, p.GetIRI())
	})

	t.Run("WithObject", func(t *testing.T) {
		p := NewObjectProperty(WithObject(NewObject(WithType(TypeVerifiableCredential), WithID(objectPropertyID))))
		require.NotNil(t, p)

		typeProp := p.GetType()
		require.Nil(t, p.GetIRI())
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))
	})
}

func TestObjectProperty_MarshalJSON(t *testing.T) {
	t.Run("WithIRI", func(t *testing.T) {
		iri := mustParseURL("https://example.com/obj1")

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
				WithContext(ContextOrb),
			),
		))
		require.NotNil(t, p)

		bytes, err := json.Marshal(p)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonEmbeddedObjectProperty), string(bytes))
	})
}

func TestObjectProperty_UnmarshalJSON(t *testing.T) {
	t.Run("WithIRI", func(t *testing.T) {
		iri := mustParseURL("https://example.com/obj1")

		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonIRIObjectProperty), p))

		require.Nil(t, p.GetType())
		require.Nil(t, p.GetObject())
		require.Equal(t, iri, p.GetIRI())
	})

	t.Run("WithObject", func(t *testing.T) {
		p := NewObjectProperty()
		require.NoError(t, json.Unmarshal([]byte(jsonEmbeddedObjectProperty), p))

		require.Nil(t, p.GetIRI())

		typeProp := p.GetType()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))

		obj := p.GetObject()
		require.NotNil(t, obj)

		context := obj.GetContext()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextOrb))

		require.Equal(t, objectPropertyID, obj.GetID())

		typeProp = obj.GetType()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))
	})
}

const (
	objectPropertyID = "some_obj_ID"

	jsonIRIObjectProperty = `"https://example.com/obj1"`

	jsonEmbeddedObjectProperty = `{
  "@context": "https://trustbloc.github.io/Context/orb-v1.json",
  "id": "some_obj_ID",
  "type": "VerifiableCredential"
}`
)
