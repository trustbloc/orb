/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestAnchorEventNil(t *testing.T) {
	var anchorEvent *AnchorEventType

	require.Nil(t, anchorEvent.Object())
}

func TestAnchorEvent(t *testing.T) {
	contentObj := &sampleContentObj{Field1: "value1", Field2: "value2"}

	contentDoc, err := MarshalToDoc(contentObj)
	require.NoError(t, err)

	anchorHL, err := hashlink.New().CreateHashLink(testutil.MarshalCanonical(t, contentObj), nil)
	require.NoError(t, err)

	anchorEvent := NewAnchorEvent(
		NewObjectProperty(WithDocument(contentDoc)),
		WithContext(ContextActivityStreams),
		WithURL(testutil.MustParseURL(anchorHL)),
	)

	bytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	require.NoError(t, err)

	t.Logf("Anchor event: %s", bytes)

	require.Equal(t, testutil.GetCanonical(t, jsonAnchorEvent), string(bytes))

	ae := &AnchorEventType{}
	require.NoError(t, json.Unmarshal(bytes, ae))
	require.NoError(t, ae.Validate())
}

func TestAnchorEventType_Validate(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		data := struct {
			Field string
		}{Field: "value"}

		dataBytes, err := canonicalizer.MarshalCanonical(data)
		require.NoError(t, err)

		hl, err := hashlink.New().CreateHashLink(dataBytes, nil)
		require.NoError(t, err)

		doc, err := UnmarshalToDoc(dataBytes)
		require.NoError(t, err)

		ae := NewAnchorEvent(
			NewObjectProperty(WithDocument(doc)),
			WithURL(MustParseURL(hl)),
		)

		require.NoError(t, ae.Validate())
	})

	t.Run("Nil anchor event -> error", func(t *testing.T) {
		var ae *AnchorEventType

		require.EqualError(t, ae.Validate(), "nil anchor event")
	})

	t.Run("No URL -> error", func(t *testing.T) {
		ae := NewAnchorEvent(nil)

		require.EqualError(t, ae.Validate(), "url is required")
	})

	t.Run("No object -> success", func(t *testing.T) {
		ae := NewAnchorEvent(nil, WithURL(MustParseURL("hl:dcdscecec")))

		require.NoError(t, ae.Validate())
	})

	t.Run("Invalid anchor URI -> error", func(t *testing.T) {
		data := struct {
			Field string
		}{Field: "value"}

		dataBytes, err := canonicalizer.MarshalCanonical(data)
		require.NoError(t, err)

		doc, err := UnmarshalToDoc(dataBytes)
		require.NoError(t, err)

		ae := NewAnchorEvent(
			NewObjectProperty(WithDocument(doc)),
			WithURL(MustParseURL("hl:uEiDhi1oX6K76A1ch5WPu2wdNLcizCx08EypO0taw9KHOGw")),
		)

		err = ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match the hash of the object")
	})
}

func TestAnchorEventType_JustURL(t *testing.T) {
	anchorEvent := NewAnchorEvent(
		nil,
		WithURL(testutil.MustParseURL(
			"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk",
		)),
	)

	bytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	require.NoError(t, err)

	t.Logf("Anchor event: %s", bytes)

	require.Equal(t, testutil.GetCanonical(t, jsonAnchorEventRef), string(bytes))

	require.NoError(t, anchorEvent.Validate())
}

//nolint:tagliatelle
type sampleContentObj struct {
	Field1 string `json:"field_1"`
	Field2 string `json:"field_2"`
}

const (
	jsonAnchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "object": {
    "field_1": "value1",
    "field_2": "value2"
  },
  "type": "AnchorEvent",
  "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA"
}`

	jsonAnchorEventRef = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "type": "AnchorEvent",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`
)
