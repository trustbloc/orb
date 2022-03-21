/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbtestgenerator

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
)

const (
	coreIndexHL1             = "hl:uEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg"                                                                                                                                                                                                         //nolint:lll
	coreIndexHL1WithMetadata = "hl:uEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ" //nolint:lll
	coreIndexHL2             = "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg:uoQ-BeEJpcGZzOi8vYmFma3JlaWU1bWJyeHlpZGUzenBhd2RtcGc3NmV5NDUyamE3dmVhd3hod2ZucXdhdHQ1cmt1YjdlbGk"                                                                                                        //nolint:lll
	suffix1                  = "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
	suffix2                  = "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw"
	parentHL1                = "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"                                                                                                              //nolint:lll
	parentHL1WithMetadata    = "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE" //nolint:lll
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

const (
	//nolint:lll
	jsonAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg",
      "author": "",
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
      "profile": "https://w3id.org/orb#v777"
    }
  ]
}`
)
