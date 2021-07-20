/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package builder

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/subject"
)

func TestSigner_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		builderParams := Params{
			Issuer: "issuer",
			URL:    "url",
		}

		b, err := New(builderParams)
		require.NoError(t, err)
		require.NotNil(t, b)
	})

	t.Run("error - missing issuer", func(t *testing.T) {
		s, err := New(Params{})
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "failed to verify builder parameters: missing issuer")
	})

	t.Run("error - missing URL", func(t *testing.T) {
		s, err := New(Params{Issuer: "issuer"})
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "failed to verify builder parameters: missing URL")
	})
}

func TestBuilder_Build(t *testing.T) {
	builderParams := Params{
		Issuer: "issuer",
		URL:    "http://domain.com/vc",
	}

	previousAnchors := make(map[string]string)
	previousAnchors["suffix"] = ""

	t.Run("success", func(t *testing.T) {
		b, err := New(builderParams)
		require.NoError(t, err)

		vc, err := b.Build(&subject.Payload{Namespace: "did:orb", PreviousAnchors: previousAnchors})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
	})

	t.Run("error - invalid namespace", func(t *testing.T) {
		b, err := New(builderParams)
		require.NoError(t, err)

		vc, err := b.Build(&subject.Payload{Namespace: "doc:something", PreviousAnchors: previousAnchors})
		require.Error(t, err)
		require.Empty(t, vc)
		require.Contains(t, err.Error(),
			"failed to build anchor activity: failed to create generator: generator not defined for namespace: doc:something")
	})
}

func TestSigner_verifyBuilderParams(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		builderParams := Params{
			Issuer: "issuer",
			URL:    "http://domain.com/vc",
		}

		err := verifyBuilderParams(builderParams)
		require.NoError(t, err)
	})

	t.Run("error - missing issuer", func(t *testing.T) {
		err := verifyBuilderParams(Params{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing issuer")
	})
}
