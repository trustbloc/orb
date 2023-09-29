/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbtestgenerator

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
)

const (
	coreIndexHL1             = "hl:uEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg"
	coreIndexHL1WithMetadata = "hl:uEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ"
	coreIndexHL2             = "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg:uoQ-BeEJpcGZzOi8vYmFma3JlaWU1bWJyeHlpZGUzenBhd2RtcGc3NmV5NDUyamE3dmVhd3hod2ZucXdhdHQ1cmt1YjdlbGk"
	suffix1                  = "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
	suffix2                  = "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw"
	parentHL1                = "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
	parentHL1WithMetadata    = "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE"
	parentMH1                = "uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
	service1                 = "https://domain1.com/services/orb"

	multihashPrefix  = "did:orb"
	unpublishedLabel = "uAAA"
)

func TestNew(t *testing.T) {
	t.Run("Default ID, Namespace, Version", func(t *testing.T) {
		gen := New()
		require.NotNil(t, gen)

		require.Equal(t, ID, gen.ID().String())
		require.Equal(t, Namespace, gen.Namespace())
		require.Equal(t, Version, gen.Version())
	})
}

func TestGenerator_CreateContentObject(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	t.Run("Success", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL2,
			PreviousAnchors: []*subject.SuffixAnchor{
				{
					Suffix: suffix1,
				},
				{
					Suffix: suffix2,
					Anchor: "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE",
				},
			},
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.NoError(t, err)
		require.NotNil(t, contentObj)

		contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
		require.NoError(t, err)

		t.Logf("ContentObject: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonAnchorLinkset), string(contentObjBytes))
	})

	t.Run("No core index", func(t *testing.T) {
		payload := &subject.Payload{}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing core index")
		require.Nil(t, contentObj)
	})
}

func TestGenerator_GetPayloadFromAnchorLink(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	items := []*linkset.Item{
		linkset.NewItem(testutil.MustParseURL(fmt.Sprintf("%s:%s:%s", multihashPrefix, unpublishedLabel, suffix1)),
			nil),
		linkset.NewItem(testutil.MustParseURL(fmt.Sprintf("%s:%s:%s", multihashPrefix, parentMH1, suffix2)),
			testutil.MustParseURL(parentHL1)),
	}

	al := linkset.NewAnchorLink(
		testutil.MustParseURL(coreIndexHL1),
		testutil.MustParseURL(service1),
		testutil.MustParseURL(ID),
		items,
	)

	originalLSDoc, err := vocab.MarshalToDoc(linkset.New(al))
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		payload, err := gen.CreatePayload(
			originalLSDoc,
			testutil.MustParseURL(coreIndexHL1WithMetadata),
			[]*url.URL{testutil.MustParseURL(parentHL1WithMetadata)},
		)
		require.NoError(t, err)
		require.NotNil(t, payload)

		require.Equal(t, coreIndexHL1WithMetadata, payload.CoreIndex)
		require.Equal(t, Namespace, payload.Namespace)
		require.Equal(t, Version, payload.Version)
		require.Equal(t, service1, payload.AnchorOrigin)
		require.Equal(t, "", payload.PreviousAnchors[0].Anchor)
		require.Equal(t, "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw", payload.PreviousAnchors[0].Suffix)
		require.Equal(t, parentHL1WithMetadata, payload.PreviousAnchors[1].Anchor)
		require.Equal(t, "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw", payload.PreviousAnchors[1].Suffix)
	})
}

func TestGenerator_ValidateAnchorCredentialSubject(t *testing.T) {
	vc, err := verifiable.ParseCredential([]byte(jsonVC),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		verifiable.WithStrictValidation(),
	)
	require.NoError(t, err)
	require.NoError(t, New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, jsonOriginalLinkset)))
}

const (
	jsonAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg",
      "author": [
        {
          "href": ""
        }
      ],
      "item": [
        {
          "href": "did:orb:uAAA:EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
        },
        {
          "href": "did:orb:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw",
          "previous": [
            "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
          ]
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v777"
        }
      ]
    }
  ]
}`

	jsonVC = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "hl:uEiDvjtGoMhXcaTYxoLrayFmmtlg2Xh2IWlYTXajyqI8CkA",
    "href": "hl:uEiCf1PSLM67NpIDuxeg9pR47SEax_S_NRQmQ-sy2NfXQaA",
    "rel": "linkset",
    "profile": "https://w3id.org/orb#v777",
    "type": "AnchorLink"
  },
  "id": "https://orb.domain1.com/vc/95bd0a07-cd90-423a-87da-0bd2b4d0c00e",
  "issuanceDate": "2022-07-20T19:14:03.3350642Z",
  "issuer": "https://orb.domain1.com",
  "proof": [
    {
      "created": "2022-07-20T19:14:03.345Z",
      "domain": "http://orb.vct:8077/maple2020",
      "proofPurpose": "assertionMethod",
      "proofValue": "zmoH8sQ8cV3qsPLmwYipdGgaPbXCU3AmFeKCHjGgSsvq39C5mw6P5RThCaR4hLcUVTqnH1F57qqp3Do9M5sn7DQZ",
      "type": "Ed25519Signature2020",
      "verificationMethod": "did:web:orb.domain1.com#3Y4eVe4CCLL-CmBEiSkjgXxdZ_EwK7QU1Qqa0bcGlx0"
    },
    {
      "created": "2022-07-20T19:14:03.426188Z",
      "domain": "https://orb.domain2.com",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5WfMrXTZHrESbcmV4KMNrGVVr5ZNYg6ZFr2Y9xaoS9Xuvaxhgwnrkkg8PHxdb9h6uj3kemJ4UwzkHPXkyqZwASCy",
      "type": "Ed25519Signature2020",
      "verificationMethod": "did:web:orb.domain2.com#bJk8awgfjHcg8x0gzO4W9ctBCN9vI3BGLr8usMt9SkE"
    }
  ],
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

	jsonOriginalLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiDvjtGoMhXcaTYxoLrayFmmtlg2Xh2IWlYTXajyqI8CkA",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uEiBykP_SkWZoWZfKX1S0-Y2-NDJDGafmlE5q6OMJmAsYXg:EiCmr3DKudaBCve75CRdHF_B3FcdWxtQo8gjL_UhZG9oQg",
          "previous": [
            "hl:uEiBykP_SkWZoWZfKX1S0-Y2-NDJDGafmlE5q6OMJmAsYXg"
          ]
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v777"
        }
      ]
    }
  ]
}`
)
