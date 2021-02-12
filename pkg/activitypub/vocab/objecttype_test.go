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
)

func TestObjectType_WithoutDocument(t *testing.T) {
	const id = "http://sally.example.com/transactions/bafkreihwsn"

	to1 := mustParseURL("https://to1")
	to2 := mustParseURL("https://to2")

	publishedTime := getStaticTime()
	startTime := getStaticTime()
	endTime := getStaticTime()

	t.Run("NewObject", func(t *testing.T) {
		obj := NewObject(
			WithID(id),
			WithContext(ContextCredentials, ContextOrb),
			WithType(TypeVerifiableCredential, TypeAnchorCredential),
			WithTo(to1, to2),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)

		context := obj.GetContext()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextOrb))

		require.Equal(t, id, obj.GetID())

		typeProp := obj.GetType()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential, TypeAnchorCredential))

		require.Equal(t, &publishedTime, obj.GetPublished())
		require.Equal(t, &startTime, obj.GetStartTime())
		require.Equal(t, &endTime, obj.GetEndTime())

		to := obj.GetTo()
		require.Len(t, to, 2)
		require.Equal(t, to1.String(), to[0].String())
		require.Equal(t, to2.String(), to[1].String())
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		obj := NewObject(
			WithID(id),
			WithContext(ContextCredentials, ContextOrb),
			WithType(TypeVerifiableCredential, TypeAnchorCredential),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)

		bytes, err := canonicalizer.MarshalCanonical(obj)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonObject), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		obj := NewObject()
		require.NoError(t, json.Unmarshal([]byte(jsonObject), obj))

		t.Logf("Types: %s", obj.object.Type.types)

		context := obj.GetContext()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextOrb))

		require.Equal(t, id, obj.GetID())

		typeProp := obj.GetType()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential, TypeAnchorCredential))

		require.Equal(t, &publishedTime, obj.GetPublished())
		require.Equal(t, &startTime, obj.GetStartTime())
		require.Equal(t, &endTime, obj.GetEndTime())

		require.Len(t, obj.GetTo(), 0)
	})
}

func TestObjectType_WithDocument(t *testing.T) {
	const id = "http://sally.example.com/transactions/bafkreihwsn"

	to1 := mustParseURL("https://to1")
	to2 := mustParseURL("https://to2")

	publishedTime := getStaticTime()
	startTime := getStaticTime()
	endTime := getStaticTime()

	t.Run("MarshalJSON", func(t *testing.T) {
		obj, err := NewObjectWithDocument(
			Document{
				"credentialSubject": Document{
					"anchorString": "bafkreihwsn",
					"namespace":    "did:orb",
					"previousTransactions": Document{
						"EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
						"EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w",
					},
					"version": "1",
				},
				"issuanceDate": "2021-01-27T09:30:10Z",
				"issuer":       "https://sally.example.com/services/orb",
				"proofChain":   []interface{}{},
			},
			WithID(id),
			WithContext(ContextCredentials, ContextOrb),
			WithType(TypeVerifiableCredential, TypeAnchorCredential),
			WithTo(to1, to2),
			WithPublishedTime(&publishedTime),
			WithStartTime(&startTime),
			WithEndTime(&endTime),
		)
		require.NoError(t, err)

		bytes, err := canonicalizer.MarshalCanonical(obj)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonObjectWithDoc), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		obj := &ObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonObjectWithDoc), obj))

		t.Logf("Types: %s", obj.object.Type.types)

		context := obj.GetContext()
		require.NotNil(t, context)
		require.True(t, context.Contains(ContextCredentials, ContextOrb))

		require.Equal(t, id, obj.GetID())

		typeProp := obj.GetType()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeVerifiableCredential, TypeAnchorCredential))
	})

	t.Run("Error", func(t *testing.T) {
		obj, err := NewObjectWithDocument(nil)
		require.EqualError(t, err, "nil document")
		require.Nil(t, obj)
	})
}

const (
	jsonObject = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/Context/orb-v1.json"
  ],
  "endTime": "2021-01-27T09:30:10Z",
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "published": "2021-01-27T09:30:10Z",
  "startTime": "2021-01-27T09:30:10Z",
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`
	jsonObjectWithDoc = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/Context/orb-v1.json"
  ],
  "endTime": "2021-01-27T09:30:10Z",
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "published": "2021-01-27T09:30:10Z",
  "startTime": "2021-01-27T09:30:10Z",
  "to": [
    "https://to1",
    "https://to2"
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
  "proofChain": [],
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`
)
