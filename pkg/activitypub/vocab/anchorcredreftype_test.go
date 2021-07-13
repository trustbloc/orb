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

const cid = "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

var (
	anchorCredIRI = newMockID(host1, "/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")
	txID          = testutil.MustParseURL("https://org1.com/transactions/tx1")
)

func TestNewAnchorCredentialReference(t *testing.T) {
	t.Run("No document", func(t *testing.T) {
		ref := NewAnchorCredentialReference(txID, anchorCredIRI, cid,
			WithTarget(
				NewObjectProperty(
					WithObject(
						NewObject(WithID(anchorCredIRI), WithCID(cid), WithType(TypeContentAddressedStorage)),
					),
				),
			),
		)

		require.NotNil(t, ref)
		require.Equal(t, txID.String(), ref.ID().String())

		contextProp := ref.Context()
		require.NotNil(t, contextProp)
		require.True(t, contextProp.Contains(ContextActivityStreams, ContextOrb))

		typeProp := ref.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeAnchorCredentialRef))

		targetProp := ref.Target()
		require.NotNil(t, targetProp)

		targetObjProp := targetProp.Object()
		require.NotNil(t, targetObjProp)
		require.Equal(t, anchorCredIRI.String(), targetObjProp.ID().String())
		require.Equal(t, cid, targetObjProp.CID())

		targetTypeProp := targetObjProp.Type()
		require.NotNil(t, targetTypeProp)
		require.True(t, targetTypeProp.Is(TypeContentAddressedStorage))
	})

	t.Run("With document", func(t *testing.T) {
		ref, err := NewAnchorCredentialReferenceWithDocument(txID, anchorCredIRI, cid, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil document")
		require.Nil(t, ref)

		ref, err = NewAnchorCredentialReferenceWithDocument(txID, anchorCredIRI, cid,
			MustUnmarshalToDoc([]byte(anchorCredential)),
		)
		require.NoError(t, err)

		require.NotNil(t, ref)
		require.Equal(t, txID.String(), ref.ID().String())

		contextProp := ref.Context()
		require.NotNil(t, contextProp)
		require.True(t, contextProp.Contains(ContextActivityStreams, ContextOrb))

		typeProp := ref.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeAnchorCredentialRef))

		targetProp := ref.Target()
		require.NotNil(t, targetProp)

		targetObjProp := targetProp.Object()
		require.NotNil(t, targetObjProp)
		require.Equal(t, anchorCredIRI.String(), targetObjProp.ID().String())
		require.Equal(t, cid, targetObjProp.CID())

		targetTypeProp := targetObjProp.Type()
		require.NotNil(t, targetTypeProp)
		require.True(t, targetTypeProp.Is(TypeContentAddressedStorage))

		refObjProp := ref.Object()
		require.NotNil(t, refObjProp)

		refObj := refObjProp.Object()
		require.NotNil(t, refObj)

		refObjType := refObj.Type()
		require.NotNil(t, refObjType)
		require.True(t, refObjType.Is(TypeVerifiableCredential, TypeAnchorCredential))

		refObjContext := refObj.Context()
		require.NotNil(t, refObjContext)
		require.True(t, refObjContext.Contains(ContextCredentials, ContextOrb))
	})
}

func TestAnchorCredentialReferenceMarshal(t *testing.T) {
	t.Run("Marshal", func(t *testing.T) {
		ref := NewAnchorCredentialReference(txID, anchorCredIRI, cid,
			WithTarget(
				NewObjectProperty(
					WithObject(
						NewObject(WithID(anchorCredIRI), WithCID(cid), WithType(TypeContentAddressedStorage)),
					),
				),
			),
		)

		bytes, err := canonicalizer.MarshalCanonical(ref)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, anchorCredentialReference), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		ref := &AnchorCredentialReferenceType{}
		require.NoError(t, json.Unmarshal([]byte(anchorCredentialReference), ref))

		require.Equal(t, txID.String(), ref.ID().String())

		contextProp := ref.Context()
		require.NotNil(t, contextProp)
		require.True(t, contextProp.Contains(ContextActivityStreams, ContextOrb))

		typeProp := ref.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeAnchorCredentialRef))

		targetProp := ref.Target()
		require.NotNil(t, targetProp)

		targetObjProp := targetProp.Object()
		require.NotNil(t, targetObjProp)
		require.Equal(t, anchorCredIRI.String(), targetObjProp.ID().String())
		require.Equal(t, cid, targetObjProp.CID())

		targetTypeProp := targetObjProp.Type()
		require.NotNil(t, targetTypeProp)
		require.True(t, targetTypeProp.Is(TypeContentAddressedStorage))
	})

	t.Run("Marshal with document", func(t *testing.T) {
		ref, err := NewAnchorCredentialReferenceWithDocument(txID, anchorCredIRI, cid,
			MustUnmarshalToDoc([]byte(anchorCredential)),
		)
		require.NoError(t, err)

		bytes, err := canonicalizer.MarshalCanonical(ref)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, anchorCredentialReferenceWithDoc), string(bytes))
	})

	t.Run("Unmarshal with doc", func(t *testing.T) {
		ref := &AnchorCredentialReferenceType{}
		require.NoError(t, json.Unmarshal([]byte(anchorCredentialReferenceWithDoc), ref))

		require.NotNil(t, ref)
		require.Equal(t, txID.String(), ref.ID().String())

		contextProp := ref.Context()
		require.NotNil(t, contextProp)
		require.True(t, contextProp.Contains(ContextActivityStreams, ContextOrb))

		typeProp := ref.Type()
		require.NotNil(t, typeProp)
		require.True(t, typeProp.Is(TypeAnchorCredentialRef))

		targetProp := ref.Target()
		require.NotNil(t, targetProp)

		targetObjProp := targetProp.Object()
		require.NotNil(t, targetObjProp)
		require.Equal(t, anchorCredIRI.String(), targetObjProp.ID().String())
		require.Equal(t, cid, targetObjProp.CID())

		targetTypeProp := targetObjProp.Type()
		require.NotNil(t, targetTypeProp)
		require.True(t, targetTypeProp.Is(TypeContentAddressedStorage))

		refObjProp := ref.Object()
		require.NotNil(t, refObjProp)

		refObj := refObjProp.Object()
		require.NotNil(t, refObj)

		refObjType := refObj.Type()
		require.NotNil(t, refObjType)
		require.True(t, refObjType.Is(TypeVerifiableCredential, TypeAnchorCredential))

		refObjContext := refObj.Context()
		require.NotNil(t, refObjContext)
		require.True(t, refObjContext.Contains(ContextCredentials, ContextOrb))
	})
}

const (
	anchorCredential = `{
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
  "proof": {}
}`
	anchorCredentialReference = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "https://org1.com/transactions/tx1",
  "target": {
    "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "cid": "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "type": "ContentAddressedStorage"
  },
  "type": "AnchorCredentialReference"
}`
	anchorCredentialReferenceWithDoc = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "https://org1.com/transactions/tx1",
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
  "target": {
    "id": "https://sally.example.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "type": "ContentAddressedStorage",
    "cid":  "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"
  },
  "type": "AnchorCredentialReference"
}`
)
