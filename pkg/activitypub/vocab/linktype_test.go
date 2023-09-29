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

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

var href = MustParseURL("hl:uEiDaKXK8DrWLEz-mJk9JCvhVpBg6DUiR-84p8cuG_kLKwg")

func TestNewLink(t *testing.T) {
	t.Run("Nil type", func(t *testing.T) {
		var link *LinkType

		require.Nil(t, link.HRef())
		require.True(t, link.Type().Is(TypeLink))
		require.False(t, link.Rel().Is(RelationshipWitness))
	})

	t.Run("Success", func(t *testing.T) {
		link := NewLink(href, RelationshipWitness)
		require.NotNil(t, link)
		require.True(t, link.Type().Is(TypeLink))
		require.NotNil(t, link.HRef())
		require.Equal(t, href.String(), link.HRef().String())
		require.True(t, link.Rel().Is(RelationshipWitness))
	})
}

func TestLinkType_MarshalJSON(t *testing.T) {
	link := NewLink(href, RelationshipWitness)
	require.NotNil(t, link)

	linkBytes, err := canonicalizer.MarshalCanonical(link)
	require.NoError(t, err)

	t.Logf("Link: %s", linkBytes)

	require.Equal(t, testutil.GetCanonical(t, jsonLink), string(linkBytes))
}

func TestLinkType_UnmarshalJSON(t *testing.T) {
	link := &LinkType{}

	require.NoError(t, json.Unmarshal([]byte(jsonLink), &link))
	require.True(t, link.Type().Is(TypeLink))
	require.NotNil(t, link.HRef())
	require.Equal(t, href.String(), link.HRef().String())
	require.True(t, link.Rel().Is(RelationshipWitness))
}

const (
	jsonLink = `{
  "href": "hl:uEiDaKXK8DrWLEz-mJk9JCvhVpBg6DUiR-84p8cuG_kLKwg",
  "rel": ["witness"],
  "type": "Link"
}`
)
