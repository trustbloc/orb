/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNilAnchorEventLink(t *testing.T) {
	var l *AnchorLinkWithReplies

	require.Nil(t, l.Anchor())
	require.Nil(t, l.Profile())
	require.Nil(t, l.Original())
	require.Empty(t, l.Original().Type())
	require.Nil(t, l.Original().HRef())
	require.Nil(t, l.Replies())
}

func TestNilAnchorLink(t *testing.T) {
	var l *AnchorLink

	require.Nil(t, l.Anchor())
	require.Nil(t, l.Profile())
	require.Nil(t, l.Up())
	require.Nil(t, l.Items())
	require.Nil(t, l.Author())
}

//nolint:lll
func TestLinksetMarshalUnmarshal(t *testing.T) {
	profile := testutil.MustParseURL("https://w3id.org/orb#v0")

	sidetreeIndexHL := testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg")

	itemHRef1 := testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA")
	prevHRef1 := testutil.MustParseURL("hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw")
	upHRef1 := testutil.MustParseURL("hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc")

	itemHRef2 := testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB")

	author := testutil.MustParseURL("https://orb.domain2.com/services/orb")

	originalLinkset := NewAnchorLinkset(
		NewAnchorLink(sidetreeIndexHL, author, profile,
			[]*Item{
				NewItem(itemHRef1, prevHRef1),
				NewItem(itemHRef2, nil),
			},
			[]*url.URL{upHRef1},
		),
	)

	originalLSBytes := testutil.MarshalCanonical(t, originalLinkset)

	t.Logf("Original: %s", originalLSBytes)

	require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalLSBytes))

	t.Run("application/gzip;base64 encoding -> success", func(t *testing.T) {
		t.Run("marshal -> success", func(t *testing.T) {
			anchor, originalRef, err := NewAnchorRef(originalLSBytes, MediaTypeDataURIGzipBase64, TypeLinkset)
			require.NoError(t, err)

			reply1DataURI, err := NewDataURI([]byte(testutil.GetCanonical(t, replyJSONData)), MediaTypeDataURIGzipBase64)
			require.NoError(t, err)

			reply2DataURI, err := NewDataURI([]byte(testutil.GetCanonical(t, replyJSONData)), MediaTypeDataURIGzipBase64)
			require.NoError(t, err)

			ls := NewAnchorLinksetWithReplies(
				NewAnchorLinkWithReplies(anchor, profile, originalRef,
					WithReply(
						NewReference(reply1DataURI, TypeJSONLD),
						NewReference(reply2DataURI, TypeJSONLD),
					),
				),
			)

			lsBytes := testutil.MarshalCanonical(t, ls)

			t.Logf("AnchorLinksetWithReplies: %s", lsBytes)

			require.Equal(t, testutil.GetCanonical(t, linksetGZIPBase64JSON), string(lsBytes))
		})

		t.Run("unmarshal -> success", func(t *testing.T) {
			ls := &AnchorLinksetWithReplies{}
			require.NoError(t, json.Unmarshal([]byte(linksetGZIPBase64JSON), ls))

			require.Len(t, ls.Linkset, 1)

			link := ls.Linkset[0]
			require.NotNil(t, link)

			require.NoError(t, link.Validate())

			originalBytes, err := link.Original().Content()
			require.NoError(t, err)

			require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalBytes))

			anchorLS := &AnchorLinkset{}
			require.NoError(t, json.Unmarshal(originalBytes, anchorLS))

			require.Len(t, anchorLS.Linkset, 1)

			anchorLink := anchorLS.Linkset[0]

			require.NoError(t, anchorLink.Validate())

			require.Equal(t, sidetreeIndexHL.String(), anchorLink.Anchor().String())
		})
	})

	t.Run("application/json encoding -> success", func(t *testing.T) {
		t.Run("marshal -> success", func(t *testing.T) {
			anchor, originalRef, err := NewAnchorRef(originalLSBytes, MediaTypeDataURIJSON, TypeLinkset)
			require.NoError(t, err)

			reply1DataURI, err := NewDataURI([]byte(testutil.GetCanonical(t, replyJSONData)), MediaTypeDataURIJSON)
			require.NoError(t, err)

			reply2DataURI, err := NewDataURI([]byte(testutil.GetCanonical(t, replyJSONData)), MediaTypeDataURIJSON)
			require.NoError(t, err)

			ls := NewAnchorLinksetWithReplies(
				NewAnchorLinkWithReplies(anchor, profile, originalRef,
					WithReply(
						NewReference(reply1DataURI, TypeJSONLD),
						NewReference(reply2DataURI, TypeJSONLD),
					),
				),
			)

			lsBytes := testutil.MarshalCanonical(t, ls)

			t.Logf("AnchorLinksetWithReplies: %s", lsBytes)

			require.Equal(t, testutil.GetCanonical(t, linksetURLEncodedJSON), string(lsBytes))
		})

		t.Run("unmarshal -> success", func(t *testing.T) {
			ls := &AnchorLinksetWithReplies{}
			require.NoError(t, json.Unmarshal([]byte(linksetURLEncodedJSON), ls))

			require.Len(t, ls.Linkset, 1)

			link := ls.Linkset[0]
			require.NotNil(t, link)

			require.NoError(t, link.Validate())

			require.NotNil(t, link.Profile())
			require.Equal(t, profile.String(), link.Profile().String())

			require.Len(t, link.Replies(), 2)

			require.NotNil(t, link.Original())

			originalLSBytes, err := link.Original().Content()
			require.NoError(t, err)

			require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalLSBytes))

			originalLS := &AnchorLinkset{}
			require.NoError(t, json.Unmarshal(originalLSBytes, originalLS))
			require.Len(t, originalLS.Linkset, 1)

			anchorLink := originalLS.Linkset[0]

			require.NotNil(t, anchorLink.Anchor())
			require.Equal(t, sidetreeIndexHL.String(), anchorLink.Anchor().String())

			require.NotNil(t, anchorLink.Author())
			require.Equal(t, author.String(), anchorLink.Author().String())

			require.Len(t, anchorLink.Items(), 2)
			require.Equal(t, itemHRef1.String(), anchorLink.Items()[0].HRef().String())
			require.Equal(t, prevHRef1.String(), anchorLink.Items()[0].Previous().String())
			require.Equal(t, itemHRef2.String(), anchorLink.Items()[1].HRef().String())

			require.Len(t, anchorLink.Up(), 1)
			require.Equal(t, upHRef1.String(), anchorLink.Up()[0].String())

			require.Equal(t, profile.String(), anchorLink.Profile().String())
		})
	})

	t.Run("Unmarshal -> error", func(t *testing.T) {
		t.Run("AnchorLinkWithReplies", func(t *testing.T) {
			l := &AnchorLinkWithReplies{}
			require.Error(t, l.UnmarshalJSON([]byte("}")))
		})

		t.Run("AnchorLink", func(t *testing.T) {
			l := &AnchorLink{}
			require.Error(t, l.UnmarshalJSON([]byte("}")))
		})

		t.Run("Reference", func(t *testing.T) {
			r := &Reference{}
			require.Error(t, r.UnmarshalJSON([]byte("}")))
		})

		t.Run("Item", func(t *testing.T) {
			i := &Item{}
			require.Error(t, i.UnmarshalJSON([]byte("}")))
		})
	})
}

func TestAnchorLink_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		l := NewAnchorLink(
			testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			[]*Item{
				NewItem(
					testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA"),
					nil,
				),
			},
			nil,
		)
		require.NoError(t, l.Validate())
	})

	t.Run("nil link -> error", func(t *testing.T) {
		var l *AnchorLink
		require.EqualError(t, l.Validate(), "nil link")
	})

	t.Run("nil anchor URI -> error", func(t *testing.T) {
		l := NewAnchorLink(
			nil,
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			[]*Item{
				NewItem(
					testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA"),
					nil,
				),
			},
			nil,
		)
		require.EqualError(t, l.Validate(), "anchor URI is required")
	})

	t.Run("nil author URI -> error", func(t *testing.T) {
		l := NewAnchorLink(
			testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg"),
			nil,
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			[]*Item{
				NewItem(
					testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA"),
					nil,
				),
			},
			nil,
		)
		require.EqualError(t, l.Validate(), "author URI is required")
	})

	t.Run("nil profile URI -> error", func(t *testing.T) {
		l := NewAnchorLink(
			testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			nil,
			[]*Item{
				NewItem(
					testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA"),
					nil,
				),
			},
			nil,
		)
		require.EqualError(t, l.Validate(), "profile URI is required")
	})

	t.Run("no items -> error", func(t *testing.T) {
		l := NewAnchorLink(
			testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			nil, nil,
		)
		require.EqualError(t, l.Validate(), "at least one item is required")
	})
}

//nolint:lll
func TestAnchorLinkWithReplies_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
		)
		require.NoError(t, l.Validate())
	})

	t.Run("nil link -> error", func(t *testing.T) {
		var l *AnchorLinkWithReplies
		require.EqualError(t, l.Validate(), "nil link")
	})

	t.Run("nil anchor -> error", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			nil,
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
		)
		require.EqualError(t, l.Validate(), "anchor URI is required")
	})

	t.Run("invalid anchor hashlink -> error", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			testutil.MustParseURL("https://someurl"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
		)
		require.EqualError(t, l.Validate(), "anchor URI is not a valid hashlink: https://someurl")
	})

	t.Run("nil profile -> error", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			nil,
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
		)
		require.EqualError(t, l.Validate(), "profile URI is required")
	})

	t.Run("invalid original content -> error", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKsdss"),
				TypeLinkset,
			),
		)
		err := l.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data at input byte")
	})

	t.Run("anchor hash mismatch -> error", func(t *testing.T) {
		l := NewAnchorLinkWithReplies(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKwHvjg"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
		)
		require.EqualError(t, l.Validate(), "hash of the original content does not match the anchor hash")
	})
}

const (
	//nolint:lll
	originalLinksetJSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg",
      "author": "https://orb.domain2.com/services/orb",
      "item": [
        {
          "href": "did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA",
          "previous": "hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw"
        },
        {
          "href": "did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "up": [
        "hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc"
      ]
    }
  ]
}`

	//nolint:lll
	replyJSONData = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "credentialSubject": "hl:uEiD96Zjp10atu2DPV1VbSxZmMvk5r5iAvSlnXXAfpkpY9g",
  "id": "https://orb.domain2.com/vc/afeead95-8507-460b-a73c-cf9b4853b4a9",
  "issuanceDate": "2022-02-22T15:45:41.6601759Z",
  "issuer": "https://orb.domain2.com",
  "proof": [
    {
      "created": "2022-02-22T15:45:41.6613096Z",
      "domain": "https://orb.domain2.com",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Sp1wXzI69pontDt-x26KwEBFhEzif33io9lIEHEEBRHgiLAFr4D6XDDVyjMmSCXWWuYBMZUFWwwHJkpPi08Dg",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain2.com#orb2key"
    },
    {
      "created": "2022-02-22T15:45:42.664Z",
      "domain": "http://orb.vct:8077/maple2020",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.._vShdZ5z_YKjWfKPt5zgTJpUoYx1pMfjETiFVHHVsZrUlAM9CXLSjrRAzGicT4uqTVFqurrpsQstPAABpm_DDQ",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain1.com#orb1key2"
    }
  ],
  "type": "VerifiableCredential"
}`

	//nolint:lll
	linksetGZIPBase64JSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiDMut3ejYHWvds0PajgKg9zy9OqwWZTirAQob6tp42kog",
      "original": {
        "href": "data:application/gzip;base64,H4sIAAAAAAAA/6TQX4+aQBQF8O9y+4qKtGvivA2VVYzgH5ZR2JgGZgYZBQZhGHQ3fvfGpmn63D7f3JzfOZ9QiOrScgXo/ROSiuayAQR5gTpHfCckGFRmfzPXGXcOtjc907m/pp6Dmyjab9zb5WX2o5hO7sEJDEg69ftbqbpFo5Fs0iGTZSIqa0hlOWp5owXl7fMABgjFy1+xecMzQMAEQ7JJUYcxRo6ws/2V42Xm+HyxwnYbuVHZuld1GaRtqZel3E3ckxuwSUwxGFA3XAvZtX/0mOBNfua9F+qkn5mnYuBF3od+25AuxONZvR4HpX2l8zTXPTyM/2ZgZsPj+ITITBT8rx36r4INZXN69v6iTTCgqwG9/4MTdXI7sLmjJFvsevoh9cqa3iPxckmtcZ7sv91Xpa/TYHqODp5mIam3JLbDeX6ND8wnhzhn5raPrV69kcLnVRyGr/GYhM5tt7A3HvHVtno976ylZBWF4+P4+BkAAP//kmCCUyECAAA=",
        "type": "application/linkset+json"
      },
      "profile": "https://w3id.org/orb#v0",
      "replies": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/7yTXXOiPBiG/0veU+UjAgpHrwpWbG21+Emn0wkQNAgkTYKonf73HXbb7s7utEc7e5rkue65r8nzAv6PaSnxSQLnAeylZMJR1bqulbqjUL5Toab31JjjBJeSoFyoRx08tsDPk6CKMhxL4IB97lQecW0rzJiuIVlBd7bSV1FwCovp8WByk/SPQV5uNv2UHdjW3oEWIEkz+ZZLeaQktECkhEpMC/UYqyjFGCW22e6ZWrdtWFrURt1O3I5TOzJ6ZicykN1ghKhQGWMXSQwcADUI2xpsQ7jQTccwHUNXLEvTu6Ydvr3G/PNg0AKMU5oC5+GlqYokTj6l6h3NthrqD8CX1KwWwAH4PNlHVzG5I5NR6N0v5oEv/MKHt0PfCouRiOFS+MXtGW3m5C4XZJttNT/XbUWBAdPrzcW3bEZL6cr2CVrXtTcY7b0LSTsdQu3c98aeN7gf78hNf8QN19q47uqcTYtguFmvq+1gGi5H67oeTw5sRrSeu3uvO6s4o6Lxh4TAXBJaTrHc0wS0gDyz5sJLoGnqdkB2JZIVx833AC1wxJykJEa/jDggIYlT48j5TcN/lEfwgM/gtfW1XKhYlvGH2Devx1g6Pa3bVQvEcgw1qP0FvU/HYJ+E5uVpe52t0+uZNC+7xYQt6faks2maeQsyWo3HKxHyZd6f2sPNTZDx+/7lisQLo3perEbPFedMzIWc9fsDVjy57vyf6dXf9eoHfIbg9fGDu/oOQFGOhx+LC16/BQAA//8oVea0/QMAAA==",
          "type": "application/ld+json"
        },
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/7yTXXOiPBiG/0veU+UjAgpHrwpWbG21+Emn0wkQNAgkTYKonf73HXbb7s7utEc7e5rkue65r8nzAv6PaSnxSQLnAeylZMJR1bqulbqjUL5Toab31JjjBJeSoFyoRx08tsDPk6CKMhxL4IB97lQecW0rzJiuIVlBd7bSV1FwCovp8WByk/SPQV5uNv2UHdjW3oEWIEkz+ZZLeaQktECkhEpMC/UYqyjFGCW22e6ZWrdtWFrURt1O3I5TOzJ6ZicykN1ghKhQGWMXSQwcADUI2xpsQ7jQTccwHUNXLEvTu6Ydvr3G/PNg0AKMU5oC5+GlqYokTj6l6h3NthrqD8CX1KwWwAH4PNlHVzG5I5NR6N0v5oEv/MKHt0PfCouRiOFS+MXtGW3m5C4XZJttNT/XbUWBAdPrzcW3bEZL6cr2CVrXtTcY7b0LSTsdQu3c98aeN7gf78hNf8QN19q47uqcTYtguFmvq+1gGi5H67oeTw5sRrSeu3uvO6s4o6Lxh4TAXBJaTrHc0wS0gDyz5sJLoGnqdkB2JZIVx833AC1wxJykJEa/jDggIYlT48j5TcN/lEfwgM/gtfW1XKhYlvGH2Devx1g6Pa3bVQvEcgw1qP0FvU/HYJ+E5uVpe52t0+uZNC+7xYQt6faks2maeQsyWo3HKxHyZd6f2sPNTZDx+/7lisQLo3perEbPFedMzIWc9fsDVjy57vyf6dXf9eoHfIbg9fGDu/oOQFGOhx+LC16/BQAA//8oVea0/QMAAA==",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

	//nolint:lll
	linksetURLEncodedJSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiDMut3ejYHWvds0PajgKg9zy9OqwWZTirAQob6tp42kog",
      "original": {
        "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain2.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA%22%2C%22previous%22%3A%22hl%3AuEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%22hl%3AuEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc%22%5D%7D%5D%7D",
        "type": "application/linkset+json"
      },
      "profile": "https://w3id.org/orb#v0",
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiD96Zjp10atu2DPV1VbSxZmMvk5r5iAvSlnXXAfpkpY9g%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain2.com%2Fvc%2Fafeead95-8507-460b-a73c-cf9b4853b4a9%22%2C%22issuanceDate%22%3A%222022-02-22T15%3A45%3A41.6601759Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-02-22T15%3A45%3A41.6613096Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Sp1wXzI69pontDt-x26KwEBFhEzif33io9lIEHEEBRHgiLAFr4D6XDDVyjMmSCXWWuYBMZUFWwwHJkpPi08Dg%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%2C%7B%22created%22%3A%222022-02-22T15%3A45%3A42.664Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.._vShdZ5z_YKjWfKPt5zgTJpUoYx1pMfjETiFVHHVsZrUlAM9CXLSjrRAzGicT4uqTVFqurrpsQstPAABpm_DDQ%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        },
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiD96Zjp10atu2DPV1VbSxZmMvk5r5iAvSlnXXAfpkpY9g%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain2.com%2Fvc%2Fafeead95-8507-460b-a73c-cf9b4853b4a9%22%2C%22issuanceDate%22%3A%222022-02-22T15%3A45%3A41.6601759Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-02-22T15%3A45%3A41.6613096Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Sp1wXzI69pontDt-x26KwEBFhEzif33io9lIEHEEBRHgiLAFr4D6XDDVyjMmSCXWWuYBMZUFWwwHJkpPi08Dg%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%2C%7B%22created%22%3A%222022-02-22T15%3A45%3A42.664Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.._vShdZ5z_YKjWfKPt5zgTJpUoYx1pMfjETiFVHHVsZrUlAM9CXLSjrRAzGicT4uqTVFqurrpsQstPAABpm_DDQ%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
)
