/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoctransformer

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/document/webresolver/mocks"
)

const (
	webDID = "did:web:orb.domain1.com:scid:" + testSuffix

	testSuffix            = "EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw"
	testUnpublishedSuffix = "EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw"
)

//nolint:forcetypeassert
func TestWebDocumentFromOrbDocument(t *testing.T) {
	t.Run("success - published did with also known as", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2],
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")

		responseBytes, err := json.Marshal(response)
		require.NoError(t, err)

		fmt.Println(string(responseBytes))
	})

	t.Run("success - unpublished did (orb unpublished ID added to also known as)", func(t *testing.T) {
		var unpublishedResolutionResult document.ResolutionResult
		err := json.Unmarshal([]byte(unpublishedDIDResolutionResult), &unpublishedResolutionResult)
		require.NoError(t, err)

		response, err := WebDocumentFromOrbDocument(webDID, &unpublishedResolutionResult)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testUnpublishedSuffix, response.ID())
		require.Equal(t, 3, len(response[document.AlsoKnownAs].([]string)))
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2],
			"did:orb:https:orb.domain1.com:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")

		responseBytes, err := json.Marshal(response)
		require.NoError(t, err)

		fmt.Println(string(responseBytes))
	})

	t.Run("success - published did but domain not in alsoKnownAs (orb canonical ID added to also known as)", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(rr, nil)

		otherWebDID := "did:web:other.com:scid:" + testSuffix

		response, err := WebDocumentFromOrbDocument(otherWebDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:other.com:scid:"+testSuffix, response.ID())
		require.Equal(t, 4, len(response[document.AlsoKnownAs].([]string)))
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:web:orb.domain1.com:scid:"+testSuffix)
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
	})

	t.Run("success - also known as does not exist in the document", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		delete(rr.Document, document.AlsoKnownAs)

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
	})

	t.Run("success - equivalent ID does not exist in the document", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		delete(rr.DocumentMetadata, document.EquivalentIDProperty)

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, 2, len(response[document.AlsoKnownAs].([]string)))
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
	})

	t.Run("success - also known as is string array", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		rr.Document[document.AlsoKnownAs] = document.StringArray(rr.Document[document.AlsoKnownAs])

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2],
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
	})

	t.Run("success - equivalent ID is string array", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		rr.DocumentMetadata[document.EquivalentIDProperty] = []string{"https://test.com"}

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, 3, len(response[document.AlsoKnownAs].([]string)))
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "https://myblog.example/")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2], "https://test.com")
	})

	t.Run("success - current domain not listed in also known as(string array version)", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		rr.Document[document.AlsoKnownAs] = []string{"other.com"}

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.NoError(t, err)
		require.NotNil(t, response)

		require.Equal(t, "did:web:orb.domain1.com:scid:"+testSuffix, response.ID())
		require.Equal(t, 3, len(response[document.AlsoKnownAs].([]string)))
		require.Equal(t, response[document.AlsoKnownAs].([]string)[0], "other.com")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[1],
			"did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
		require.Equal(t, response[document.AlsoKnownAs].([]string)[2],
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw")
	})

	t.Run("error - also known as is an unexpected interface", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		rr.Document[document.AlsoKnownAs] = 123

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "unexpected interface 'float64' for also known as")
	})

	t.Run("error - equivalent ID is an unexpected interface", func(t *testing.T) {
		rr, err := getTestResolutionResult()
		require.NoError(t, err)

		rr.DocumentMetadata[document.EquivalentIDProperty] = 123

		response, err := WebDocumentFromOrbDocument(webDID, rr)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "unexpected interface 'int' for equivalentId")
	})
}

func TestVerifyWebDocumentFromOrbDocument(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		webRR, err := getResolutionResult(webResponse)
		require.NoError(t, err)

		orbRR, err := getResolutionResult(orbResponse)
		require.NoError(t, err)

		err = VerifyWebDocumentFromOrbDocument(webRR, orbRR)
		require.NoError(t, err)
	})

	t.Run("error - documents do not match", func(t *testing.T) {
		webRR, err := getResolutionResult(`{"didDocument": {}}`)
		require.NoError(t, err)

		orbRR, err := getResolutionResult(orbResponse)
		require.NoError(t, err)

		err = VerifyWebDocumentFromOrbDocument(webRR, orbRR)
		require.Error(t, err)
		require.Contains(t, err.Error(), "do not match")
	})

	t.Run("error - parse also known as error", func(t *testing.T) {
		webRR, err := getResolutionResult(`{}`)
		require.NoError(t, err)

		orbRR, err := getResolutionResult(`{"didDocument": {"alsoKnownAs": 1}}`)
		require.NoError(t, err)

		err = VerifyWebDocumentFromOrbDocument(webRR, orbRR)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected interface 'float64' for also known as")
	})
}

func TestEqual(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		doc1, err := getDocument(`{"id" : "some-id"}`)
		require.NoError(t, err)

		doc2, err := getDocument(`{"id" : "some-id"}`)
		require.NoError(t, err)

		err = Equal(doc1, doc2)
		require.NoError(t, err)
	})

	t.Run("success - empty doc", func(t *testing.T) {
		doc1, err := getDocument("{}")
		require.NoError(t, err)

		doc2, err := getDocument("{}")
		require.NoError(t, err)

		err = Equal(doc1, doc2)
		require.NoError(t, err)
	})

	t.Run("success - with exclude tag", func(t *testing.T) {
		doc1, err := getDocument(`{}`)
		require.NoError(t, err)

		doc2, err := getDocument(`{"alsoKnownAs": ["did:web:hello.com"]}`)
		require.NoError(t, err)

		err = Equal(doc1, doc2, "alsoKnownAs")
		require.NoError(t, err)
	})

	t.Run("error - not equal", func(t *testing.T) {
		doc1, err := getDocument(`{"id" : "some-id"}`)
		require.NoError(t, err)

		doc2, err := getDocument(`{"id" : "other-id"}`)
		require.NoError(t, err)

		err = Equal(doc1, doc2)
		require.Error(t, err)
		require.Contains(t, err.Error(), `documents [{"id":"some-id"}] and [{"id":"other-id"}] do not match`)
	})
}

func getTestResolutionResult() (*document.ResolutionResult, error) {
	return getResolutionResult(didResolutionResult)
}

func getResolutionResult(str string) (*document.ResolutionResult, error) {
	var docResolutionResult document.ResolutionResult

	err := json.Unmarshal([]byte(str), &docResolutionResult)
	if err != nil {
		return nil, err
	}

	return &docResolutionResult, nil
}

func getDocument(str string) (document.Document, error) {
	var doc document.Document

	err := json.Unmarshal([]byte(str), &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

var didResolutionResult = `
{
 "@context": "https://w3id.org/did-resolution/v1",
 "didDocument": {
  "@context": [
   "https://www.w3.org/ns/did/v1",
   "https://w3id.org/security/suites/jws-2020/v1",
   "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "alsoKnownAs": [
   "https://myblog.example/",
   "did:web:orb.domain1.com:scid:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw"
  ],
  "assertionMethod": [
   "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#auth"
  ],
  "authentication": [
   "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#createKey"
  ],
  "id": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
  "service": [
   {
    "id": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#didcomm",
    "priority": 0,
    "recipientKeys": [
     "6UNXSmh2pMmW5fFCiEzA8mKRDuv3MTfnFzNykrAjrvoa"
    ],
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
    "type": "did-communication"
   }
  ],
  "verificationMethod": [
   {
    "controller": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
    "id": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#createKey",
    "publicKeyJwk": {
     "crv": "P-256",
     "kty": "EC",
     "x": "dqC44RPG5B_N5_I3a7U_MLdgOdaDCpFX31fn16wglYk",
     "y": "JtXp469K2WZXKe-isBZGMVWOfB44JOuZJPLF3ofgcpw"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
    "id": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#auth",
    "publicKeyBase58": "CfKvprZ9TpFdE2ZAsr9czZmSFChwcsVa2LBYngfwyFdM",
    "type": "Ed25519VerificationKey2018"
   }
  ]
 },
 "didDocumentMetadata": {
  "canonicalId": "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
  "created": "2022-08-22T17:04:13Z",
  "equivalentId": [
   "did:orb:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
   "did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
   "did:orb:https:shared.domain.com:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw"
  ],
  "method": {
   "anchorOrigin": "https://orb.domain1.com",
   "published": true,
   "publishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "canonicalReference": "uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ",
     "equivalentReferences": [
      "hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ",
      "https:shared.domain.com:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ"
     ],
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiNlVOWFNtaDJwTW1XNWZGQ2lFekE4bUtSRHV2M01UZm5Gek55a3JBanJ2b2EiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1hbHNvLWtub3duLWFzIiwidXJpcyI6WyJodHRwczovL215YmxvZy5leGFtcGxlLyJdfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiZHFDNDRSUEc1Ql9ONV9JM2E3VV9NTGRnT2RhRENwRlgzMWZuMTZ3Z2xZayIsInkiOiJKdFhwNDY5SzJXWlhLZS1pc0JaR01WV09mQjQ0Sk91WkpQTEYzb2ZnY3B3In0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiclVJSFp1QjZ0LXRncEhIS2lfQ1VnaWRtUXdYWGlZODJtRkV6eHN3dTQxUSIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlEYTV1Q3gtNXNUc0FoNEJmT1U4UXFTSW5sV1huV1pQTUdlb21ZeElrNjNQUSJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlBcmxIZXBob1o0bXJSVVJBV1VfTGhJSGJqNFB0X0FSSFZ4Vy01MGhYM0FodyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQWQzYlhMV1VRWVljTUtGb0FJb0hUbjJTeTdudktoVWcwZFREUGtPV3lpekEifSwidHlwZSI6ImNyZWF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1661187853,
     "type": "create"
    },
    {
     "canonicalReference": "uEiDoMxcf-STXWHlBBi1PRWxycekYDST1EV-uokiAbxih7Q",
     "equivalentReferences": [
      "hl:uEiDoMxcf-STXWHlBBi1PRWxycekYDST1EV-uokiAbxih7Q:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRG9NeGNmLVNUWFdIbEJCaTFQUld4eWNla1lEU1QxRVYtdW9raUFieGloN1F4QmlwZnM6Ly9iYWZrcmVpaGlnbWxyNzZqZTI1bWhzcWlnZnZodWszZHNvaHVycWRqZTZ1aXY3bHZjamNhZzZnZmI1dQ",
      "https:shared.domain.com:uEiDoMxcf-STXWHlBBi1PRWxycekYDST1EV-uokiAbxih7Q"
     ],
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtYWxzby1rbm93bi1hcyIsInVyaXMiOlsiZGlkOndlYjpvcmIuZG9tYWluMS5jb206aWQ6RWlCbVBIT0dlNGY4TDRfWlZnQmc1VjM0M19uRFNTWDNsNlgtOVZLUmhFNTdUdyJdfV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJyMkQ1Z1B4X1dwbnVseXZja3YyUnl2RVJld1laUGxIUnNpWU45eWlhNVl3In0sImRpZFN1ZmZpeCI6IkVpQm1QSE9HZTRmOEw0X1pWZ0JnNVYzNDNfbkRTU1gzbDZYLTlWS1JoRTU3VHciLCJyZXZlYWxWYWx1ZSI6IkVpQVhucDdnQ2YyTXpwV2NUREZkY2lLNTVXd1NEbDZBd2pNWGdLa3VOVWJfdHciLCJzaWduZWREYXRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKaGJtTm9iM0pHY205dElqb3hOall4TVRnM09EVTBMQ0poYm1Ob2IzSlZiblJwYkNJNk1UWTJNVEU0T0RFMU5Dd2laR1ZzZEdGSVlYTm9Jam9pUldsRWNISkVXVFIzY1RsMVkwWk5Na1JWWm5wWlNGUk9RM0ZvV2xsek1uVXphRkJHWW1oeGFWZEZlbkY2UVNJc0luVndaR0YwWlV0bGVTSTZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SW5GM1prRnpWWFl5ZDJaTlJ6TndjbkkyVEZkWVlrMVpWVlEyTjBWVWJuWjVTVlo2TmtwbU9XaFVTbGtpTENKNUlqb2liVXRVTFhKcGVqSlVkelJsYzBWb1EyNDBhRXBYVkVaRFltMUNNVFpmVkVONllXcGhVM0ZYY0VWV1dTSjlmUS5Mbk1tbnE1b2dSMzhMRVRBbHVpWDNTQ052aWJpREstc2VXY3drU1VCdGQzUzhWSzd1a2trR2FJNzVGQ2taaWlaWngwclBzeWJLb2tCQkVINk9rLVhTUSIsInR5cGUiOiJ1cGRhdGUifQ==",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1661187855,
     "type": "update"
    }
   ],
   "recoveryCommitment": "EiAd3bXLWUQYYcMKFoAIoHTn2Sy7nvKhUg0dTDPkOWyizA",
   "updateCommitment": "EiBr2D5gPx_Wpnulyvckv2RyvERewYZPlHRsiYN9yia5Yw"
  },
  "updated": "2022-08-22T17:04:15Z",
  "versionId": "uEiDoMxcf-STXWHlBBi1PRWxycekYDST1EV-uokiAbxih7Q"
 }
}`

var unpublishedDIDResolutionResult = `
{
 "@context": "https://w3id.org/did-resolution/v1",
 "didDocument": {
  "@context": [
   "https://www.w3.org/ns/did/v1",
   "https://w3id.org/security/suites/jws-2020/v1",
   "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "alsoKnownAs": [
   "https://myblog.example/"
  ],
  "assertionMethod": [
   "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#auth"
  ],
  "authentication": [
   "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#createKey"
  ],
  "id": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
  "service": [
   {
    "id": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#didcomm",
    "priority": 0,
    "recipientKeys": [
     "6UNXSmh2pMmW5fFCiEzA8mKRDuv3MTfnFzNykrAjrvoa"
    ],
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
    "type": "did-communication"
   }
  ],
  "verificationMethod": [
   {
    "controller": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
    "id": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#createKey",
    "publicKeyJwk": {
     "crv": "P-256",
     "kty": "EC",
     "x": "dqC44RPG5B_N5_I3a7U_MLdgOdaDCpFX31fn16wglYk",
     "y": "JtXp469K2WZXKe-isBZGMVWOfB44JOuZJPLF3ofgcpw"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw",
    "id": "did:orb:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw#auth",
    "publicKeyBase58": "CfKvprZ9TpFdE2ZAsr9czZmSFChwcsVa2LBYngfwyFdM",
    "type": "Ed25519VerificationKey2018"
   }
  ]
 },
 "didDocumentMetadata": {
  "equivalentId": [
   "did:orb:https:orb.domain1.com:uAAA:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw"
  ],
  "method": {
   "anchorOrigin": "https://orb.domain1.com",
   "published": false,
   "recoveryCommitment": "EiAd3bXLWUQYYcMKFoAIoHTn2Sy7nvKhUg0dTDPkOWyizA",
   "updateCommitment": "EiDa5uCx-5sTsAh4BfOU8QqSInlWXnWZPMGeomYxIk63PQ"
  }
 }
}`

var webResponse = `
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://w3id.org/security/suites/ed25519-2018/v1"
    ],
    "alsoKnownAs": [
      "https://myblog.example/",
      "did:orb:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
      "did:orb:hl:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4zLmNvbS9jYXMvdUVpQ3hGR0N6Z2QwZ1Rrb0xobkV6UDZBT3d2TThGSG40UVRUYjVZamxXNHVRSFE:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA"
    ],
    "assertionMethod": [
      "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#auth"
    ],
    "authentication": [
      "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#createKey"
    ],
    "id": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
    "service": [
      {
        "id": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#didcomm",
        "priority": 0,
        "recipientKeys": [
          "9kQ8WK6mj32d3v6SZp6bzngPajta2KPMd92qjcQZ4bLG"
        ],
        "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
        "type": "did-communication"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
        "id": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#createKey",
        "publicKeyJwk": {
          "crv": "P-256",
          "kty": "EC",
          "x": "k2WMSkwqKWZR6imfF1Nv-OLJLhylNJMX1n8_dRGlYuE",
          "y": "2ES0qDhNfbMe9CimiYj69zU60mhrXVwVlcwKwhW_DVs"
        },
        "type": "JsonWebKey2020"
      },
      {
        "controller": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
        "id": "did:web:orb.domain3.com:scid:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#auth",
        "publicKeyBase58": "VM6LMBqwetP9yLJo9C6nZkA4B4LwLA5ZkqeTstp8vdq",
        "type": "Ed25519VerificationKey2018"
      }
    ]
  }
}`

var orbResponse = `
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://w3id.org/security/suites/ed25519-2018/v1"
    ],
    "alsoKnownAs": [
      "https://myblog.example/"
    ],
    "assertionMethod": [
      "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#auth"
    ],
    "authentication": [
      "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#createKey"
    ],
    "id": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
    "service": [
      {
        "id": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#didcomm",
        "priority": 0,
        "recipientKeys": [
          "9kQ8WK6mj32d3v6SZp6bzngPajta2KPMd92qjcQZ4bLG"
        ],
        "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
        "type": "did-communication"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
        "id": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#createKey",
        "publicKeyJwk": {
          "crv": "P-256",
          "kty": "EC",
          "x": "k2WMSkwqKWZR6imfF1Nv-OLJLhylNJMX1n8_dRGlYuE",
          "y": "2ES0qDhNfbMe9CimiYj69zU60mhrXVwVlcwKwhW_DVs"
        },
        "type": "JsonWebKey2020"
      },
      {
        "controller": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
        "id": "did:orb:uAAA:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA#auth",
        "publicKeyBase58": "VM6LMBqwetP9yLJo9C6nZkA4B4LwLA5ZkqeTstp8vdq",
        "type": "Ed25519VerificationKey2018"
      }
    ]
  },
  "didDocumentMetadata": {
    "canonicalId": "did:orb:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
    "created": "2022-08-31T19:13:44Z",
    "equivalentId": [
      "did:orb:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
      "did:orb:hl:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4zLmNvbS9jYXMvdUVpQ3hGR0N6Z2QwZ1Rrb0xobkV6UDZBT3d2TThGSG40UVRUYjVZamxXNHVRSFE:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA",
      "did:orb:https:shared.domain.com:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:EiAWS5rfPpy3KK_3l7_aPb4sZsCraVCxFM-SeEqWrVi0RA"
    ],
    "method": {
      "anchorOrigin": "https://orb.domain3.com",
      "published": true,
      "publishedOperations": [
        {
          "type": "create",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtYWxzby1rbm93bi1hcyIsInVyaXMiOlsiaHR0cHM6Ly9teWJsb2cuZXhhbXBsZS8iXX0seyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImNyZWF0ZUtleSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImsyV01Ta3dxS1daUjZpbWZGMU52LU9MSkxoeWxOSk1YMW44X2RSR2xZdUUiLCJ5IjoiMkVTMHFEaE5mYk1lOUNpbWlZajY5elU2MG1oclhWd1ZsY3dLd2hXX0RWcyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifSx7ImlkIjoiYXV0aCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkIwTDdEMmoydU9VMUNHeXR4aGtzOHVUU3hCZTFIWC1ISUtlWVUwVmZKelEiLCJ5IjoiIn0sInB1cnBvc2VzIjpbImFzc2VydGlvbk1ldGhvZCJdLCJ0eXBlIjoiRWQyNTUxOVZlcmlmaWNhdGlvbktleTIwMTgifV19LHsiYWN0aW9uIjoiYWRkLXNlcnZpY2VzIiwic2VydmljZXMiOlt7ImlkIjoiZGlkY29tbSIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbIjlrUThXSzZtajMyZDN2NlNacDZiem5nUGFqdGEyS1BNZDkycWpjUVo0YkxHIl0sInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vaHViLmV4YW1wbGUuY29tLy5pZGVudGl0eS9kaWQ6ZXhhbXBsZTowMTIzNDU2Nzg5YWJjZGVmLyIsInR5cGUiOiJkaWQtY29tbXVuaWNhdGlvbiJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlCZkcxRjVjcmp6cE1pYzhZdG9DTXNPd0c2SlJ4eDhBZWx1dEhrVjV5UXp0ZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjMuY29tIiwiZGVsdGFIYXNoIjoiRWlDYVc1SEI4MWxabWJYVE9FUDFLMVpLVmpGRmhoOVg4clZuSERMNHFBbzQxUSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQkJ0Ump3UmQ1N3JVYmlodGQ1NU5TMlVFR1Bvc0lqV3EtY1hWdHlQS0Z0OWcifSwidHlwZSI6ImNyZWF0ZSJ9",
          "transactionTime": 1661973224,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ",
          "equivalentReferences": [
            "hl:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4zLmNvbS9jYXMvdUVpQ3hGR0N6Z2QwZ1Rrb0xobkV6UDZBT3d2TThGSG40UVRUYjVZamxXNHVRSFE",
            "https:shared.domain.com:uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ"
          ],
          "anchorOrigin": "https://orb.domain3.com"
        }
      ],
      "recoveryCommitment": "EiBBtRjwRd57rUbihtd55NS2UEGPosIjWq-cXVtyPKFt9g",
      "updateCommitment": "EiBfG1F5crjzpMic8YtoCMsOwG6JRxx8AelutHkV5yQztg"
    },
    "versionId": "uEiCxFGCzgd0gTkoLhnEzP6AOwvM8FHn4QTTb5YjlW4uQHQ"
  }
}`
