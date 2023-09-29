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

func TestNewTagProperty(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var p *TagProperty

		require.Nil(t, p.Object())
		require.Nil(t, p.Link())
		require.Nil(t, p.Type())
	})

	t.Run("No object or link", func(t *testing.T) {
		p := NewTagProperty()

		require.Nil(t, p.Object())
		require.Nil(t, p.Type())
		require.Nil(t, p.Type())
	})

	t.Run("Link type", func(t *testing.T) {
		p := NewTagProperty(WithLink(NewLink(href, RelationshipWitness)))
		require.NotNil(t, p)
		require.True(t, p.Type().Is(TypeLink))
		require.NotNil(t, p.Link())
		require.Nil(t, p.Object())
	})

	t.Run("Object type", func(t *testing.T) {
		p := NewTagProperty(WithObject(NewObject(WithType(TypeService))))
		require.NotNil(t, p)
		require.True(t, p.Type().Is(TypeService))
		require.NotNil(t, p.Object())
		require.Nil(t, p.Link())
	})
}

func TestTagProperty_MarshalJSON(t *testing.T) {
	t.Run("Link type", func(t *testing.T) {
		p := NewTagProperty(WithLink(NewLink(href, RelationshipWitness)))
		require.NotNil(t, p)

		tagBytes, err := canonicalizer.MarshalCanonical(p)
		require.NoError(t, err)

		t.Logf("Tag: %s", tagBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonLink), string(tagBytes))
	})

	t.Run("Object type", func(t *testing.T) {
		p := NewTagProperty(WithObject(NewObject(WithType(TypeService))))
		require.NotNil(t, p)

		tagBytes, err := canonicalizer.MarshalCanonical(p)
		require.NoError(t, err)

		t.Logf("Tag: %s", tagBytes)

		require.Equal(t, `{"type":"Service"}`, string(tagBytes))
	})

	t.Run("No object or link -> error", func(t *testing.T) {
		p := NewTagProperty()
		require.NotNil(t, p)

		_, err := canonicalizer.MarshalCanonical(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "neither object or link is set on the tag property")
	})
}

func TestTagProperty_UnmarshalJSON(t *testing.T) {
	t.Run("Link type", func(t *testing.T) {
		p := &TagProperty{}

		require.NoError(t, json.Unmarshal([]byte(jsonLink), &p))
		require.True(t, p.Type().Is(TypeLink))
		require.NotNil(t, p.Link())
		require.Nil(t, p.Object())
	})

	t.Run("Object type", func(t *testing.T) {
		p := &TagProperty{}

		require.NoError(t, json.Unmarshal([]byte(`{"type":"Service"}`), &p))
		require.True(t, p.Type().Is(TypeService))
		require.Nil(t, p.Link())
		require.NotNil(t, p.Object())
	})
}
