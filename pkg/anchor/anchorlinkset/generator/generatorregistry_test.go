/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package generator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator/didorbgenerator"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator/samplegenerator"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)

	t.Run("Success", func(t *testing.T) {
		gen, err := r.Get(testutil.MustParseURL(didorbgenerator.ID))
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, didorbgenerator.ID, gen.ID().String())

		gen, err = r.Get(testutil.MustParseURL(samplegenerator.ID))
		require.NoError(t, err)
		require.NotNil(t, gen)
		require.Equal(t, samplegenerator.ID, gen.ID().String())
	})

	t.Run("Not found", func(t *testing.T) {
		gen, err := r.Get(testutil.MustParseURL("https://invalid_generator"))
		require.Error(t, err)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, gen)
	})

	t.Run("Nil URI", func(t *testing.T) {
		gen, err := r.Get(nil)
		require.Error(t, err)
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
