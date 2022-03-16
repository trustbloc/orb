/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbgenerator

import (
	"net/url"
	"testing"

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

const (
	//nolint:lll
	linksetJSON1 = `{
  "linkset": [
    {
      "anchor": "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg",
      "author": "https://orb.domain2.com/services/orb",
      "item": [
        {
          "href": "did:orb:uAAA:EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
        },
        {
          "href": "did:orb:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw",
          "previous": "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
        }
      ],
      "profile": "https://w3id.org/orb#v0"
    }
  ]
}`
	//nolint:lll
	linksetJSON2 = `{
  "linkset": [
    {
      "anchor": "hl:uEiDIMOGQVfSVbMR4uVPJYtM_dXJ4bNghS2F-DWH01uQnnQ",
      "author": "https://orb.domain2.com/services/orb",
      "item": [
        {
          "href": "did:orb:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA:EiCy2r_iTGOyQ83z_sTRF9rqdCFGU5sDV923tg2R_gI9CQ",
          "previous": "hl:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA"
        },
        {
          "href": "did:orb:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA:EiC80po42xkPwvw_AgECOF-qey3PjkfQ2VaaCVaPmIsjjg",
          "previous": "hl:uEiBy3ZwlpRi8OAthyinED8S189syAOUuoMFTZnmjMLJyVA"
        }
      ],
      "profile": "https://w3id.org/orb#v0"
    }
  ]
}`

	linksetJSONEmpty = `{"linkset": []}`
)
