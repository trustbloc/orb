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

func TestObjectType_WithoutDocument(t *testing.T) {
	id := testutil.MustParseURL("http://sally.example.com/transactions/bafkreihwsn")
	u1 := testutil.MustParseURL("http://sally.example.com/transactions/abc")
	u2 := testutil.MustParseURL("http://sally.example.com/transactions/def")
	u3 := testutil.MustParseURL("http://sally.example.com/transactions/ghi")
	to1 := testutil.MustParseURL("https://to1")
	to2 := testutil.MustParseURL("https://to2")

	publishedTime := getStaticTime()
	startTime := getStaticTime()
	endTime := getStaticTime()

	t.Run("NewObject", func(t *testing.T) {
		obj := NewObject(
			WithURL(u1, u2),
			WithContext(ContextCredentials, ContextActivityAnchors),
			WithType(TypeVerifiableCredential),
			WithTo(to1, to2),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)

		obj.SetID(id)

		context := obj.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextActivityAnchors))

		require.Equal(t, id.String(), obj.ID().String())

		require.True(t, obj.URL().Contains(u1))
		require.True(t, obj.URL().Equals(Urls{u1, u2}))
		require.False(t, obj.URL().Equals(Urls{u1, u3}))
		require.False(t, obj.URL().Equals(Urls{u1}))

		typeProp := obj.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))

		require.Equal(t, &publishedTime, obj.Published())
		require.Equal(t, &startTime, obj.StartTime())
		require.Equal(t, &endTime, obj.EndTime())

		to := obj.To()
		require.Len(t, to, 2)
		require.True(t, to.Contains(to1, to2))
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		obj := NewObject(
			WithID(id),
			WithContext(ContextCredentials, ContextActivityAnchors),
			WithType(TypeVerifiableCredential),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)

		bytes, err := canonicalizer.MarshalCanonical(obj)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonObject), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		obj := NewObject()
		require.NoError(t, json.Unmarshal([]byte(jsonObject), obj))

		t.Logf("Types: %s", obj.object.Type.types)

		context := obj.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextActivityAnchors))

		require.Equal(t, id.String(), obj.ID().String())

		typeProp := obj.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))

		require.Equal(t, &publishedTime, obj.Published())
		require.Equal(t, &startTime, obj.StartTime())
		require.Equal(t, &endTime, obj.EndTime())

		require.Len(t, obj.To(), 0)
	})
}

func TestObjectType_WithDocument(t *testing.T) {
	id := testutil.MustParseURL("http://sally.example.com/transactions/bafkreihwsn")
	to1 := testutil.MustParseURL("https://to1")
	to2 := testutil.MustParseURL("https://to2")

	publishedTime := getStaticTime()
	startTime := getStaticTime()
	endTime := getStaticTime()

	t.Run("MarshalJSON", func(t *testing.T) {
		obj, err := NewObjectWithDocument(
			Document{
				"credentialSubject": Document{},
				"issuanceDate":      "2021-01-27T09:30:10Z",
				"issuer":            "https://sally.example.com/services/orb",
				"proofChain":        []interface{}{},
			},
			WithID(id),
			WithContext(ContextCredentials, ContextActivityAnchors),
			WithType(TypeVerifiableCredential),
			WithTo(to1, to2),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)
		require.NoError(t, err)

		bytes, err := canonicalizer.MarshalCanonical(obj)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonObjectWithDoc), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		obj := &ObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonObjectWithDoc), obj))

		t.Logf("Types: %s", obj.object.Type.types)

		context := obj.Context()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextActivityAnchors))

		require.Equal(t, id.String(), obj.ID().String())

		typeProp := obj.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential))
	})

	t.Run("Error", func(t *testing.T) {
		obj, err := NewObjectWithDocument(nil)
		require.EqualError(t, err, "nil document")
		require.Nil(t, obj)
	})
}

func TestObjectType_Accessors(t *testing.T) {
	o := &ObjectType{}

	require.Nil(t, o.ID())
	require.Nil(t, o.To())
	require.Nil(t, o.EndTime())
	require.Nil(t, o.StartTime())
	require.Nil(t, o.InReplyTo())
	require.Nil(t, o.Attachment())
	require.Nil(t, o.Type())
	require.Nil(t, o.Context())
	require.Empty(t, o.CID())
	require.Nil(t, o.Published())
	require.Empty(t, o.URL())
	require.Nil(t, o.Tag())
	require.Empty(t, o.Generator())
	require.Nil(t, o.AttributedTo())
}

const (
	jsonObject = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "endTime": "2021-01-27T09:30:10Z",
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "published": "2021-01-27T09:30:10Z",
  "startTime": "2021-01-27T09:30:10Z",
  "type": "VerifiableCredential"
}`
	jsonObjectWithDoc = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "endTime": "2021-01-27T09:30:10Z",
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "published": "2021-01-27T09:30:10Z",
  "startTime": "2021-01-27T09:30:10Z",
  "to": [
    "https://to1",
    "https://to2"
  ],
  "credentialSubject": {},
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "issuer": "https://sally.example.com/services/orb",
  "proofChain": [],
  "type": "VerifiableCredential"
}`
)
