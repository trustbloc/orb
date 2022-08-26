/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbgenerator

import (
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	coreIndexHL1 = "hl:uEiBaZqszLIDqXbfh3WSVIEye9_vYCOl4KKMQ5Q9JU3NaoQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQmFacXN6TElEcVhiZmgzV1NWSUV5ZTlfdllDT2w0S0tNUTVROUpVM05hb1E" //nolint:lll
	coreIndexHL2 = "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg:uoQ-BeEJpcGZzOi8vYmFma3JlaWU1bWJyeHlpZGUzenBhd2RtcGc3NmV5NDUyamE3dmVhd3hod2ZucXdhdHQ1cmt1YjdlbGk"             //nolint:lll
	suffix1      = "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
	suffix2      = "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw"
	service1     = "https://orb.domain2.com/services/orb"
)

func TestNew(t *testing.T) {
	t.Run("Default ID, Namespace, Version", func(t *testing.T) {
		gen := New()
		require.NotNil(t, gen)

		require.Equal(t, ID, gen.ID().String())
		require.Equal(t, Namespace, gen.Namespace())
		require.Equal(t, Version, gen.Version())
	})

	t.Run("Alternate ID, Namespace, Version", func(t *testing.T) {
		const (
			id        = "https://some_other_generator#v1"
			namespace = "did:other"
			version   = uint64(1)
		)

		gen := New(WithID(testutil.MustParseURL(id)), WithNamespace(namespace), WithVersion(version))
		require.NotNil(t, gen)

		require.Equal(t, id, gen.ID().String())
		require.Equal(t, namespace, gen.Namespace())
		require.Equal(t, version, gen.Version())
	})
}

func TestGenerator_CreateContentObject(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	t.Run("Success", func(t *testing.T) {
		payload := &subject.Payload{
			OperationCount: 2,
			CoreIndex:      coreIndexHL2,
			Namespace:      "did:orb",
			AnchorOrigin:   service1,
			PreviousAnchors: []*subject.SuffixAnchor{
				{
					Suffix: suffix1,
				},
				{
					Suffix: suffix2,
					Anchor: "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE", //nolint:lll
				},
			},
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.NoError(t, err)
		require.NotNil(t, contentObj)

		contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
		require.NoError(t, err)

		t.Logf("ContentObject: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, linksetJSON1), string(contentObjBytes))
	})

	t.Run("No core index", func(t *testing.T) {
		payload := &subject.Payload{}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing core index")
		require.Nil(t, contentObj)
	})

	t.Run("No previous anchors", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL1,
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing previous anchors")
		require.Nil(t, contentObj)
	})

	t.Run("Invalid hashlink in previous anchor", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL1,
			PreviousAnchors: []*subject.SuffixAnchor{
				{
					Suffix: suffix2,
					Anchor: "uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA",
				},
			},
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of parts for previous anchor hashlink")
		require.Nil(t, contentObj)
	})
}

func TestGenerator_CreatePayload(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	coreIndexURI := testutil.MustParseURL("hl:uEiDIMOGQVfSVbMR4uVPJYtM_dXJ4bNghS2F-DWH01uQnnQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpRElNT0dRVmZTVmJNUjR1VlBKWXRNX2RYSjRiTmdoUzJGLURXSDAxdVFublE") //nolint:lll

	prevURI := testutil.MustParseURL("hl:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQnkzWndscFJpOE9BdGh5aW5FRDhTMTg5c3lBT1V1b01GVFpubWpNTEp5VkF4QmlwZnM6Ly9iYWZrcmVpZHMzd29jbGppeXhxNGF3eW9rZmhjYTdyZnY2cG50ZWFoZmYycW1jdTNncGdydGJtdHNrcQ") //nolint:lll

	t.Run("Success", func(t *testing.T) {
		anchorLinksetDoc, err := vocab.UnmarshalToDoc([]byte(linksetJSON2))
		require.NoError(t, err)

		payload, err := gen.CreatePayload(anchorLinksetDoc, coreIndexURI, []*url.URL{prevURI})
		require.NoError(t, err)
		require.NotNil(t, payload)

		require.Equal(t, coreIndexURI.String(), payload.CoreIndex)
		require.Equal(t, Namespace, payload.Namespace)
		require.Equal(t, Version, payload.Version)
		require.Equal(t, service1, payload.AnchorOrigin)
		require.Equal(t, prevURI.String(), payload.PreviousAnchors[0].Anchor)
		require.Equal(t, "EiCy2r_iTGOyQ83z_sTRF9rqdCFGU5sDV923tg2R_gI9CQ", payload.PreviousAnchors[0].Suffix)
	})

	t.Run("Empty Linkset -> error", func(t *testing.T) {
		anchorLinksetDoc, err := vocab.UnmarshalToDoc([]byte(linksetJSONEmpty))
		require.NoError(t, err)

		payload, err := gen.CreatePayload(anchorLinksetDoc, coreIndexURI, []*url.URL{prevURI})
		require.EqualError(t, err, "empty anchor Linkset")
		require.Nil(t, payload)
	})

	t.Run("Invalid core index URI -> error", func(t *testing.T) {
		anchorLinksetDoc, err := vocab.UnmarshalToDoc([]byte(linksetJSON2))
		require.NoError(t, err)

		payload, err := gen.CreatePayload(anchorLinksetDoc,
			testutil.MustParseURL("hl:uEiDhi1oX6K76A1ch5WPu2wdNLcizCx08EypO0taw9KHOGw"), []*url.URL{prevURI})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not related to core index URI")
		require.Nil(t, payload)
	})
}

func TestGenerator_ValidateAnchorCredentialSubject(t *testing.T) {
	vc, err := verifiable.ParseCredential([]byte(vcJSON),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		verifiable.WithStrictValidation(),
	)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		require.NoError(t, New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetJSON3)))
	})

	t.Run("Unmarshal anchor linkset error", func(t *testing.T) {
		err = New().ValidateAnchorCredential(vc, []byte("}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal anchor linkset: invalid character")
	})

	t.Run("Empty anchor linkset -> success", func(t *testing.T) {
		err = New().ValidateAnchorCredential(vc, []byte("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty anchor linkset")
	})

	t.Run("Unsupported profile -> success", func(t *testing.T) {
		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetUnsupportedProfileJSON))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported profile")
	})

	t.Run("Nil anchor in anchor linkset -> fail", func(t *testing.T) {
		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetNilAnchorJSON))
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor in anchor linkset is nil")
	})

	t.Run("Invalid subject href -> error", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(vcInvalidHRefJSON),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithStrictValidation(),
		)
		require.NoError(t, err)

		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetJSON3))
		require.Error(t, err)
		require.Contains(t, err.Error(), "subject href [invalid] does not match the hashlink of the content")
	})

	t.Run("Invalid profile -> error", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(vcInvalidProfileJSON),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithStrictValidation(),
		)
		require.NoError(t, err)

		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetJSON3))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"profile in the credential subject [https://invalid] does not match profile [https://w3id.org/orb#v0]")
	})

	t.Run("Invalid profile -> error", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(vcInvalidAnchorJSON),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithStrictValidation(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetJSON3))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"anchor in the credential subject [invalid] does not match the anchor in the anchor linkset")
	})

	t.Run("Invalid credentialSubject -> error", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(vcInvalidCredentialSubjectJSON),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithStrictValidation(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = New().ValidateAnchorCredential(vc, testutil.GetCanonicalBytes(t, linksetJSON3))
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing mandatory field")
	})
}

func TestParseCredentialSubject(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{
				"anchor":  "anchor1",
				"href":    "href1",
				"profile": "profile1",
				"rel":     relLinkset,
				"type":    "AnchorLink",
			},
		}}})
		require.NoError(t, err)
		require.NotNil(t, s)
		require.Equal(t, "anchor1", s.Anchor)
		require.Equal(t, "href1", s.HRef)
		require.Equal(t, "profile1", s.Profile)
		require.Equal(t, relLinkset, s.Rel)
	})

	t.Run("invalid credentialSubject error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: ""})
		require.EqualError(t, err, "invalid credentialSubject")
	})

	t.Run("unmarshal credentialSubject error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{"anchor": 1},
		}}})
		require.EqualError(t, err, "unmarshal credential subject: json: cannot unmarshal number into Go struct field CredentialSubject.anchor of type string") //nolint:lll
	})

	t.Run("missing anchor field error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{},
		}}})
		require.EqualError(t, err, `missing mandatory field "anchor" in the credential subject`)
	})

	t.Run("missing href field error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{
				"anchor": "anchor1",
			},
		}}})
		require.EqualError(t, err, `missing mandatory field "href" in the credential subject`)
	})

	t.Run("missing href field error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{
				"anchor": "anchor1",
				"href":   "href1",
			},
		}}})
		require.EqualError(t, err, `missing mandatory field "profile" in the credential subject`)
	})

	t.Run("missing href field error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{
				"anchor":  "anchor1",
				"href":    "href1",
				"profile": "profile1",
			},
		}}})
		require.EqualError(t, err, `missing mandatory field "rel" in the credential subject`)
	})

	t.Run("missing href field error", func(t *testing.T) {
		_, err := parseCredentialSubject(&verifiable.Credential{Subject: []verifiable.Subject{{
			CustomFields: map[string]interface{}{
				"anchor":  "anchor1",
				"href":    "href1",
				"profile": "profile1",
				"rel":     "invalid",
			},
		}}})
		require.EqualError(t, err, `unsupported relation type "invalid" in the credential subject`)
	})
}

const (
	//nolint:lll
	linksetJSON1 = `{
  "linkset": [
    {
      "anchor": "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg",
      "author": [
        {
          "href": "https://orb.domain2.com/services/orb"
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
          "href": "https://w3id.org/orb#v0"
        }
      ]
    }
  ]
}`
	//nolint:lll
	linksetJSON2 = `{
  "linkset": [
    {
      "anchor": "hl:uEiDIMOGQVfSVbMR4uVPJYtM_dXJ4bNghS2F-DWH01uQnnQ",
      "author": [
        {
          "href": "https://orb.domain2.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA:EiCy2r_iTGOyQ83z_sTRF9rqdCFGU5sDV923tg2R_gI9CQ",
          "previous": [
            "hl:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA"
          ]
        },
        {
          "href": "did:orb:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA:EiC80po42xkPwvw_AgECOF-qey3PjkfQ2VaaCVaPmIsjjg",
          "previous": [
            "hl:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA"
          ]
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ]
    }
  ]
}`

	linksetJSONEmpty = `{"linkset": []}`

	linksetJSON3 = `{
  "linkset": [
    {
      "anchor": "hl:uEiAgZlwuq4c6LjXLTILb1mklrZ9qqg42OEl9NNZtlL1XFw",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uAAA:EiBNTklr_Syb4tONtEIEPBLBdKgwCEOvjeTW4PwssB3Snw"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ]
    }
  ]
}`

	linksetUnsupportedProfileJSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiAgZlwuq4c6LjXLTILb1mklrZ9qqg42OEl9NNZtlL1XFw",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uAAA:EiBNTklr_Syb4tONtEIEPBLBdKgwCEOvjeTW4PwssB3Snw"
        }
      ],
      "profile": [
        {
          "href": "https://unsupported"
        }
      ]
    }
  ]
}`

	linksetNilAnchorJSON = `{
  "linkset": [
    {
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uAAA:EiBNTklr_Syb4tONtEIEPBLBdKgwCEOvjeTW4PwssB3Snw"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ]
    }
  ]
}`

	vcJSON = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "hl:uEiAgZlwuq4c6LjXLTILb1mklrZ9qqg42OEl9NNZtlL1XFw",
    "href": "hl:uEiCHU0O97gyQ8oq5O-pdxuacArLGIHu-_MFSfA4g7YSf3A",
    "rel": "linkset",
    "type": "AnchorLink",
    "profile": "https://w3id.org/orb#v0"
  },
  "id": "https://orb.domain1.com/vc/a95e6f27-f106-4486-aac9-986c5cae3be6",
  "issuanceDate": "2022-07-18T20:17:38.3799055Z",
  "issuer": "https://orb.domain1.com",
  "proof": {
    "created": "2022-07-18T20:17:38.394Z",
    "domain": "http://orb.vct:8077/maple2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Et9ksRtjxzbR9ai9B5HBG6sGMns4gPE2nDvHa5YVdbdTUeiLLmw7FfVZezvQGGbj2v42MaBU3S2h1aNfNdJSdKk",
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:orb.domain1.com#B2iVprWQpu1vorDdj19NwLTA0p73qtiGxyrkBukmt_w"
  },
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

	vcInvalidHRefJSON = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "hl:uEiAgZlwuq4c6LjXLTILb1mklrZ9qqg42OEl9NNZtlL1XFw",
    "href": "invalid",
    "rel": "linkset",
    "type": "AnchorLink",
    "profile": "https://w3id.org/orb#v0"
  },
  "id": "https://orb.domain1.com/vc/a95e6f27-f106-4486-aac9-986c5cae3be6",
  "issuanceDate": "2022-07-18T20:17:38.3799055Z",
  "issuer": "https://orb.domain1.com",
  "proof": {
    "created": "2022-07-18T20:17:38.394Z",
    "domain": "http://orb.vct:8077/maple2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Et9ksRtjxzbR9ai9B5HBG6sGMns4gPE2nDvHa5YVdbdTUeiLLmw7FfVZezvQGGbj2v42MaBU3S2h1aNfNdJSdKk",
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:orb.domain1.com#B2iVprWQpu1vorDdj19NwLTA0p73qtiGxyrkBukmt_w"
  },
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

	vcInvalidProfileJSON = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "hl:uEiAgZlwuq4c6LjXLTILb1mklrZ9qqg42OEl9NNZtlL1XFw",
    "href": "hl:uEiCHU0O97gyQ8oq5O-pdxuacArLGIHu-_MFSfA4g7YSf3A",
    "rel": "linkset",
    "type": "AnchorLink",
    "profile": "https://invalid"
  },
  "id": "https://orb.domain1.com/vc/a95e6f27-f106-4486-aac9-986c5cae3be6",
  "issuanceDate": "2022-07-18T20:17:38.3799055Z",
  "issuer": "https://orb.domain1.com",
  "proof": {
    "created": "2022-07-18T20:17:38.394Z",
    "domain": "http://orb.vct:8077/maple2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Et9ksRtjxzbR9ai9B5HBG6sGMns4gPE2nDvHa5YVdbdTUeiLLmw7FfVZezvQGGbj2v42MaBU3S2h1aNfNdJSdKk",
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:orb.domain1.com#B2iVprWQpu1vorDdj19NwLTA0p73qtiGxyrkBukmt_w"
  },
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

	vcInvalidAnchorJSON = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "invalid",
    "href": "hl:uEiCHU0O97gyQ8oq5O-pdxuacArLGIHu-_MFSfA4g7YSf3A",
    "rel": "linkset",
    "type": "AnchorLink",
    "profile": "https://w3id.org/orb#v0"
  },
  "id": "https://orb.domain1.com/vc/a95e6f27-f106-4486-aac9-986c5cae3be6",
  "issuanceDate": "2022-07-18T20:17:38.3799055Z",
  "issuer": "https://orb.domain1.com",
  "proof": {
    "created": "2022-07-18T20:17:38.394Z",
    "domain": "http://orb.vct:8077/maple2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Et9ksRtjxzbR9ai9B5HBG6sGMns4gPE2nDvHa5YVdbdTUeiLLmw7FfVZezvQGGbj2v42MaBU3S2h1aNfNdJSdKk",
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:orb.domain1.com#B2iVprWQpu1vorDdj19NwLTA0p73qtiGxyrkBukmt_w"
  },
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

	vcInvalidCredentialSubjectJSON = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "id": "xxx"
  },
  "id": "https://orb.domain1.com/vc/a95e6f27-f106-4486-aac9-986c5cae3be6",
  "issuanceDate": "2022-07-18T20:17:38.3799055Z",
  "issuer": "https://orb.domain1.com",
  "proof": {
    "created": "2022-07-18T20:17:38.394Z",
    "domain": "http://orb.vct:8077/maple2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3Et9ksRtjxzbR9ai9B5HBG6sGMns4gPE2nDvHa5YVdbdTUeiLLmw7FfVZezvQGGbj2v42MaBU3S2h1aNfNdJSdKk",
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:orb.domain1.com#B2iVprWQpu1vorDdj19NwLTA0p73qtiGxyrkBukmt_w"
  },
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`
)
