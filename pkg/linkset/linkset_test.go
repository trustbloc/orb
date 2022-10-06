/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkset

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNil(t *testing.T) {
	t.Run("nil link", func(t *testing.T) {
		var l *Link

		require.Nil(t, l.Anchor())
		require.Nil(t, l.Profile())
		require.Nil(t, l.Original())
		require.Empty(t, l.Original().Type())
		require.Nil(t, l.Original().HRef())
		require.Nil(t, l.Related())
		require.Nil(t, l.Replies())
		require.Nil(t, l.Items())
		require.Nil(t, l.Author())
		require.Nil(t, l.Up())
		require.Nil(t, l.Via())
	})

	t.Run("empty link reference", func(t *testing.T) {
		l := &Link{
			link: &link{},
		}

		require.Nil(t, l.Original())
		require.Nil(t, l.Related())
		require.Nil(t, l.Replies())
		require.Nil(t, l.Items())
		require.Nil(t, l.Up())
		require.Nil(t, l.Via())
	})

	t.Run("nil item", func(t *testing.T) {
		var item *Item

		require.Nil(t, item.HRef())
		require.Nil(t, item.Previous())
	})

	t.Run("empty item", func(t *testing.T) {
		item := &Item{}

		require.Nil(t, item.HRef())
		require.Nil(t, item.Previous())
	})

	t.Run("no URLs in item", func(t *testing.T) {
		item := NewItem(nil, nil)

		require.Nil(t, item.HRef())
		require.Nil(t, item.Previous())
	})

	t.Run("nil reference", func(t *testing.T) {
		var ref *Reference

		require.Nil(t, ref.HRef())
		require.Empty(t, ref.Type())

		content, err := ref.Content()
		require.NoError(t, err)
		require.Nil(t, content)

		ls, err := ref.Linkset()
		require.NoError(t, err)
		require.Nil(t, ls)
	})
}

func TestLinksetMarshalUnmarshal(t *testing.T) {
	profile := testutil.MustParseURL("https://w3id.org/orb#v0")

	sidetreeIndexHL := testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg")
	sidetreeIndexHLWithMetadata := testutil.MustParseURL("hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg:dcefdece89eu7987")

	itemHRef1 := testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA")
	prevHRef1 := testutil.MustParseURL("hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw")
	upHRef1 := testutil.MustParseURL("hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc")
	upHRef2 := testutil.MustParseURL("hl:uEiAVAQhjewMUvawD0gl-LYMzvTPVuUA1DpO1SmBqcGbhvw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc")

	itemHRef2 := testutil.MustParseURL("did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB")

	author := testutil.MustParseURL("https://orb.domain2.com/services/orb")

	originalLinkset := New(
		NewAnchorLink(sidetreeIndexHL, author, profile,
			[]*Item{
				NewItem(itemHRef1, prevHRef1),
				NewItem(itemHRef2, nil),
			},
		),
	)

	originalLSBytes := testutil.MarshalCanonical(t, originalLinkset)

	t.Logf("Original: %s", originalLSBytes)

	require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalLSBytes))

	t.Run("application/gzip;base64 encoding -> success", func(t *testing.T) {
		t.Run("marshal -> success", func(t *testing.T) {
			anchor, originalRef, err := NewAnchorRef(originalLSBytes, datauri.MediaTypeDataURIGzipBase64, TypeLinkset)
			require.NoError(t, err)

			upLinkset := New(
				NewRelatedLink(anchor, profile, sidetreeIndexHLWithMetadata, upHRef1, upHRef2),
			)

			upLSBytes := testutil.MarshalCanonical(t, upLinkset)

			upDataURI, err := datauri.New(upLSBytes, datauri.MediaTypeDataURIGzipBase64)
			require.NoError(t, err)

			related := NewReference(upDataURI, TypeLinkset)

			reply1DataURI, err := datauri.New([]byte(testutil.GetCanonical(t, replyJSONData)), datauri.MediaTypeDataURIGzipBase64)
			require.NoError(t, err)

			ls := New(
				NewLink(anchor, author, profile, originalRef, related,
					NewReference(reply1DataURI, TypeJSONLD),
				),
			)

			lsBytes := testutil.MarshalCanonical(t, ls)

			t.Logf("AnchorLinksetWithReplies: %s", lsBytes)

			require.Equal(t, testutil.GetCanonical(t, linksetGZIPBase64JSON), string(lsBytes))
		})

		t.Run("unmarshal -> success", func(t *testing.T) {
			ls := &Linkset{}
			require.NoError(t, json.Unmarshal([]byte(linksetGZIPBase64JSON), ls))

			require.Len(t, ls.Linkset, 1)

			link := ls.Linkset[0]
			require.NotNil(t, link)

			require.NoError(t, link.Validate())

			originalBytes, err := link.Original().Content()
			require.NoError(t, err)

			require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalBytes))

			anchorLS, err := link.Original().Linkset()
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(originalBytes, anchorLS))

			require.Len(t, anchorLS.Linkset, 1)

			anchorLink := anchorLS.Linkset[0]

			require.NoError(t, anchorLink.Validate())

			require.Equal(t, sidetreeIndexHL.String(), anchorLink.Anchor().String())
		})
	})

	anchor, originalRef, err := NewAnchorRef(originalLSBytes, datauri.MediaTypeDataURIJSON, TypeLinkset)
	require.NoError(t, err)

	t.Run("application/json encoding -> success", func(t *testing.T) {
		t.Run("marshal -> success", func(t *testing.T) {
			upLinkset := New(
				NewRelatedLink(anchor, profile, sidetreeIndexHLWithMetadata, upHRef1, upHRef2),
			)

			upLSBytes := testutil.MarshalCanonical(t, upLinkset)

			upDataURI, err := datauri.New(upLSBytes, datauri.MediaTypeDataURIJSON)
			require.NoError(t, err)

			related := NewReference(upDataURI, TypeLinkset)

			reply1DataURI, err := datauri.New([]byte(testutil.GetCanonical(t, replyJSONData)), datauri.MediaTypeDataURIJSON)
			require.NoError(t, err)

			ls := New(
				NewLink(anchor, author, profile, originalRef, related,
					NewReference(reply1DataURI, TypeJSONLD),
				),
			)

			lsBytes := testutil.MarshalCanonical(t, ls)

			t.Logf("Linkset: %s", lsBytes)

			require.Equal(t, testutil.GetCanonical(t, linksetURLEncodedJSON), string(lsBytes))
		})

		t.Run("unmarshal -> success", func(t *testing.T) {
			ls := &Linkset{}
			require.NoError(t, json.Unmarshal([]byte(linksetURLEncodedJSON), ls))

			require.Len(t, ls.Linkset, 1)

			link := ls.Linkset[0]
			require.NotNil(t, link)

			require.NoError(t, link.Validate())

			require.NotNil(t, link.Profile())
			require.Equal(t, profile.String(), link.Profile().String())

			require.NotNil(t, link.Replies())

			require.NotNil(t, link.Original())
			originalLSBytes, err := link.Original().Content()
			require.NoError(t, err)
			require.Equal(t, testutil.GetCanonical(t, originalLinksetJSON), string(originalLSBytes))

			require.NotNil(t, link.Related())
			relatedLSBytes, err := link.Related().Content()
			require.NoError(t, err)

			relatedLinkset := &Linkset{}
			require.NoError(t, json.Unmarshal(relatedLSBytes, relatedLinkset))
			require.Len(t, relatedLinkset.Linkset, 1)

			relatedLink := relatedLinkset.Linkset[0]
			require.Equal(t, anchor.String(), relatedLink.Anchor().String())
			require.Equal(t, profile.String(), relatedLink.Profile().String())
			require.Len(t, relatedLink.Up(), 2)
			require.Equal(t, upHRef1.String(), relatedLink.Up()[0].String())
			require.Equal(t, upHRef2.String(), relatedLink.Up()[1].String())
			require.NotNil(t, relatedLink.Via())
			require.Equal(t, sidetreeIndexHLWithMetadata.String(), relatedLink.Via().String())

			originalLS := &Linkset{}
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

			require.Equal(t, profile.String(), anchorLink.Profile().String())
		})
	})

	t.Run("Unmarshal -> error", func(t *testing.T) {
		t.Run("AnchorLink", func(t *testing.T) {
			l := &Link{}
			require.Error(t, l.UnmarshalJSON([]byte("}")))
		})

		t.Run("Reference", func(t *testing.T) {
			r := &Reference{}
			require.Error(t, r.UnmarshalJSON([]byte("}")))
		})

		t.Run("Related", func(t *testing.T) {
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
		)
		require.NoError(t, l.Validate())
	})

	t.Run("nil link -> error", func(t *testing.T) {
		var l *Link
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
		)
		require.EqualError(t, l.Validate(), "profile URI is required")
	})
}

func TestLink_Validate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		require.NoError(t, l.Validate())
	})

	t.Run("nil link -> error", func(t *testing.T) {
		var l *Link
		require.EqualError(t, l.Validate(), "nil link")
	})

	t.Run("nil anchor -> error", func(t *testing.T) {
		l := NewLink(
			nil,
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		require.EqualError(t, l.Validate(), "anchor URI is required")
	})

	t.Run("nil author -> error", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			nil,
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		require.EqualError(t, l.Validate(), "author URI is required")
	})

	t.Run("invalid anchor hashlink -> error", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("https://someurl"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		require.EqualError(t, l.Validate(), "anchor URI is not a valid hashlink: https://someurl")
	})

	t.Run("nil profile -> error", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			nil,
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		require.EqualError(t, l.Validate(), "profile URI is required")
	})

	t.Run("invalid original content -> error", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKoHvjg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKsdss"),
				TypeLinkset,
			),
			nil, nil,
		)
		err := l.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data at input byte")
	})

	t.Run("anchor hash mismatch -> error", func(t *testing.T) {
		l := NewLink(
			testutil.MustParseURL("hl:uEiDhwm4mNgdS5AqYulZitFOski8JXZgw5uBrTYsDKwHvjg"),
			testutil.MustParseURL("https://orb.domain2.com/services/orb"),
			testutil.MustParseURL("https://w3id.org/orb#v0"),
			NewReference(
				testutil.MustParseURL("data:application/gzip;base64,H4sIAAAAAAAA/5zOzZKaMAAA4HdJr1IBXXfkFlZWcQSVnwh0dnaEhH8IQkhwd3z3jj301ktf4JvvG9RFWw2EAe3XN7i2SU57oIG81kajeEPIlVpZTPIxJUagW+sy2drHxDJgH4aXkzlVL5vPer26uxmYgYKR5g+T9yQFGsAF1mgfayOEUDMKPb3cCNynhk12B6gPoRk2g3ljlRQPDd831FmZmeniVZRAMANdT3hBx+HvBiJ4yksiLJ9fxUbOaskKrS/undDoQ2XTHRW30W/JNs65AI/ZvxoQe461aEXVreqhVVvl9dOT2Gu5nLyluZ/cIEv1N31BpkjNwOPjGaFpUZPng7Fu0OZzsSjwT9pnc9rHP7gMZmDs/qupjfQs6cRgFO8ckXxRflDX97B4qWJVya+X5f3Q2Dx212UYWBz7qDujSPe3+S0KsI2CKMfyWUSqYB6qbdJGvv8eKcg3Jmennyxks3P7XjrqnuI2AY+Px+8AAAD//wAw1xPvAQAA"),
				TypeLinkset,
			),
			nil, nil,
		)
		err := l.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "the 'original' content does not match the anchor hash")
	})
}

func TestReference(t *testing.T) {
	anchor := testutil.MustParseURL("hl:sfsfsdf")
	author := testutil.MustParseURL("https://serve.domain1.com")
	profile := testutil.MustParseURL("https://profile.domain1.com")

	t.Run("success", func(t *testing.T) {
		data, err := json.Marshal(New(NewLink(anchor, author, profile, nil, nil, nil)))
		require.NoError(t, err)

		dataURI, err := datauri.New(data, datauri.MediaTypeDataURIGzipBase64)
		require.NoError(t, err)

		ref := NewReference(dataURI, TypeLinkset)
		require.NotNil(t, ref)

		require.Equal(t, dataURI, ref.HRef())
		require.Equal(t, TypeLinkset, ref.Type())

		contentBytes, err := ref.Content()
		require.NoError(t, err)
		require.Equal(t, data, contentBytes)

		ls, err := ref.Linkset()
		require.NoError(t, err)
		require.NotNil(t, ls.Link())

		refBytes, err := json.Marshal(ref)
		require.NoError(t, err)

		ref2 := &Reference{}

		require.NoError(t, json.Unmarshal(refBytes, ref2))
		require.Equal(t, ref.Type(), ref2.Type())
		require.Equal(t, ref.HRef().String(), ref2.HRef().String())
	})

	t.Run("content error", func(t *testing.T) {
		ref := NewReference(testutil.MustParseURL("https://invalid_data_uri"), TypeLinkset)
		require.NotNil(t, ref)

		_, err := ref.Content()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol")
	})

	t.Run("not Linkset type error", func(t *testing.T) {
		ref := NewReference(testutil.MustParseURL("https://invalid_data_uri"), TypeJSONLD)
		require.NotNil(t, ref)

		_, err := ref.Linkset()
		require.Error(t, err)
		require.Contains(t, err.Error(), "the type of the reference should be application/linkset+json")
	})

	t.Run("invalid Linkset error", func(t *testing.T) {
		ref := NewReference(testutil.MustParseURL("https://invalid_data_uri"), TypeLinkset)
		require.NotNil(t, ref)

		_, err := ref.Linkset()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid Linkset content")
	})
}

const (
	originalLinksetJSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg",
      "author": [
        {
          "href": "https://orb.domain2.com/services/orb"
        }
      ],
      "item": [
        {
          "href": "did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA",
          "previous": [
            "hl:uEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw"
          ]
        },
        {
          "href": "did:orb:uAAA:EiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB"
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

	linksetGZIPBase64JSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiDR9t1fX6jamGe2SkCbt9-FSEoIy0QDI1Bpy26zn21QoQ",
      "author": [
        {
          "href": "https://orb.domain2.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/6SQQW+6MBiHv8v7v6Lif5mJvZVJHGaoGRPHDFmgFKhSim0pbobvvmB22GG3nd88b37Pc4WK1SdFNaDDFZKalEICgrJCrcsewjAY1XZ3sTc5dV8df34ky/WG+C6WUbTfepfT/eK9ms8+ggIsSFp9ow9XKCXNhzdaNwpNJkKm40zwhNX/x0TwiaLSMELVcIA+toBpyn+CGcuQkClqMcbIZU6+P1O8yt01fXzCjoq8iCvvrE+jVHGz4uJ55hVekM3eCAYLGkkNE60CdPg2wSHelkfa+TuTdAu7qEZ+5H+al23Y7vB00WymAXfOZJmWpoO4t/48BGfOTayRImcV/S1Kd8eysZDFEOGfsaGP+7j/CgAA//+mgJC8kAEAAA==",
          "type": "application/linkset+json"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "related": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/8zQ326bMBTH8XfxbpMF2JrW3IVC0kyBxKG4wBRNYJuYP8GUGjuk4t2n9a7qC+z+6Hs++r2DpmzrNyaB/fsdZC3hogc24I09eKV7hNIs4mWVXTbMCuvHXML5OvTEdjSQuzWdbrSWt9YykUBgBrpeFGXDPkq8Z8W/jpTdm71Y6B8l/S7680L0+TdlgOk0A0P36fLj4wqvDrxi2o9Upl3j3Mz9xL+p5wMeopXpdnszvDivZJNzpe1BoLnDPCno01GTm1A7C45JeVfnlsmzl5/j7hKoPIRVEvuKRrhDOHWiDX9NYxrgOOXUQDq1tHzGTcDaNIrWqYkj73p8cg4+DiRq19XR+iVoS8A0+0pFn6m7/4V6mgFVZl/XfcQ4nLeGvhr7gnmx48OKbII98b1VnyQvh+21vnP/NHA5hmebElZQRtgDZMM9fLgH02k6TX8DAAD//5qrxNEwAgAA",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/7yTXXOiPBiG/0veU+UjAgpHrwpWbG21+Emn0wkQNAgkTYKonf73HXbb7s7utEc7e5rkue65r8nzAv6PaSnxSQLnAeylZMJR1bqulbqjUL5Toab31JjjBJeSoFyoRx08tsDPk6CKMhxL4IB97lQecW0rzJiuIVlBd7bSV1FwCovp8WByk/SPQV5uNv2UHdjW3oEWIEkz+ZZLeaQktECkhEpMC/UYqyjFGCW22e6ZWrdtWFrURt1O3I5TOzJ6ZicykN1ghKhQGWMXSQwcADUI2xpsQ7jQTccwHUNXLEvTu6Ydvr3G/PNg0AKMU5oC5+GlqYokTj6l6h3NthrqD8CX1KwWwAH4PNlHVzG5I5NR6N0v5oEv/MKHt0PfCouRiOFS+MXtGW3m5C4XZJttNT/XbUWBAdPrzcW3bEZL6cr2CVrXtTcY7b0LSTsdQu3c98aeN7gf78hNf8QN19q47uqcTYtguFmvq+1gGi5H67oeTw5sRrSeu3uvO6s4o6Lxh4TAXBJaTrHc0wS0gDyz5sJLoGnqdkB2JZIVx833AC1wxJykJEa/jDggIYlT48j5TcN/lEfwgM/gtfW1XKhYlvGH2Devx1g6Pa3bVQvEcgw1qP0FvU/HYJ+E5uVpe52t0+uZNC+7xYQt6faks2maeQsyWo3HKxHyZd6f2sPNTZDx+/7lisQLo3perEbPFedMzIWc9fsDVjy57vyf6dXf9eoHfIbg9fGDu/oOQFGOhx+LC16/BQAA//8oVea0/QMAAA==",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

	linksetURLEncodedJSON = `{
  "linkset": [
    {
      "anchor": "hl:uEiDR9t1fX6jamGe2SkCbt9-FSEoIy0QDI1Bpy26zn21QoQ",
      "author": [
        {
          "href": "https://orb.domain2.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg%22%2C%22author%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Forb.domain2.com%2Fservices%2Forb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6ZcA%22%2C%22previous%22%3A%5B%22hl%3AuEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiBfWqeAJfENeHLABsYIYmsIqtk-bsmvJmoR6IgISd6AdB%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiDR9t1fX6jamGe2SkCbt9-FSEoIy0QDI1Bpy26zn21QoQ%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiAVAPhjewMUvawD0gl-MYMzvTPVuUA1DpO1SmBqcGbhvw%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc%22%7D%2C%7B%22href%22%3A%22hl%3AuEiAVAQhjewMUvawD0gl-LYMzvTPVuUA1DpO1SmBqcGbhvw%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVZBUGhqZXdNVXZhd0QwZ2wtTVlNenZUUFZ1VUExRHBPMVNtQnFjR2Jodnc%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCVVS-n0wx0OfeEXBM9jcGNOcMEArYYWPIxk5D_l96ySg%3Adcefdece89eu7987%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiD96Zjp10atu2DPV1VbSxZmMvk5r5iAvSlnXXAfpkpY9g%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain2.com%2Fvc%2Fafeead95-8507-460b-a73c-cf9b4853b4a9%22%2C%22issuanceDate%22%3A%222022-02-22T15%3A45%3A41.6601759Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-02-22T15%3A45%3A41.6613096Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Sp1wXzI69pontDt-x26KwEBFhEzif33io9lIEHEEBRHgiLAFr4D6XDDVyjMmSCXWWuYBMZUFWwwHJkpPi08Dg%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%2C%7B%22created%22%3A%222022-02-22T15%3A45%3A42.664Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22jws%22%3A%22eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.._vShdZ5z_YKjWfKPt5zgTJpUoYx1pMfjETiFVHHVsZrUlAM9CXLSjrRAzGicT4uqTVFqurrpsQstPAABpm_DDQ%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22type%22%3A%22Ed25519Signature2018%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
)
