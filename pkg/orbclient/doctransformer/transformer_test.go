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

func TestResolveHandler_Resolve(t *testing.T) {
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
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw") //nolint:lll

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

	t.Run("success - published did but domain not in alsoKnownAs (orb canonical ID added to also known as)", func(t *testing.T) { //nolint:lll
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
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw") //nolint:lll
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
			"did:orb:hl:uEiAZPHwtTJ7-rG0nBeD6nqyL3Xsg1IA2BX1n9iGlv5yBJQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVpQSHd0VEo3LXJHMG5CZUQ2bnF5TDNYc2cxSUEyQlgxbjlpR2x2NXlCSlF4QmlwZnM6Ly9iYWZrcmVpYXpocjZjMnRlNjcyd2cyanlmNGQ1ajVsZWwzdjVzYnZlYWd5Y3gyejd3ZWdzMzdoZWJldQ:EiBmPHOGe4f8L4_ZVgBg5V343_nDSSX3l6X-9VKRhE57Tw") //nolint:lll
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

func getTestResolutionResult() (*document.ResolutionResult, error) {
	var docResolutionResult document.ResolutionResult

	err := json.Unmarshal([]byte(didResolutionResult), &docResolutionResult)
	if err != nil {
		return nil, err
	}

	return &docResolutionResult, nil
}

//nolint:lll
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
