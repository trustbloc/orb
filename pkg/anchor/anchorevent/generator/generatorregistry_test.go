/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package generator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator/didorbgenerator"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator/samplegenerator"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)

	t.Run("Success", func(t *testing.T) {
		gen, err := r.Get(didorbgenerator.ID)
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, didorbgenerator.ID, gen.ID())

		gen, err = r.Get(samplegenerator.ID)
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, samplegenerator.ID, gen.ID())
	})

	t.Run("Not found", func(t *testing.T) {
		gen, err := r.Get("https://invalid_generator")
		require.Error(t, err)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, gen)
	})
}

func TestRegistry_GetByNamespaceAndVersion(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)

	t.Run("Success", func(t *testing.T) {
		gen, err := r.GetByNamespaceAndVersion(didorbgenerator.Namespace, didorbgenerator.Version)
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, didorbgenerator.Namespace, gen.Namespace())
		require.Equal(t, didorbgenerator.Version, gen.Version())

		gen, err = r.GetByNamespaceAndVersion(samplegenerator.Namespace, samplegenerator.Version)
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, samplegenerator.Namespace, gen.Namespace())
		require.Equal(t, samplegenerator.Version, gen.Version())
	})

	t.Run("Not found", func(t *testing.T) {
		gen, err := r.GetByNamespaceAndVersion("invalid", 1)
		require.Error(t, err)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, gen)
	})
}
