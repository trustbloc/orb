/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package random

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s := New()
		require.NotNil(t, s)
	})
}

func TestSelect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s := New()
		require.NotNil(t, s)

		witnesses := []*proof.Witness{{}, {}, {}, {}}

		selected, err := s.Select(witnesses, 3)
		require.NoError(t, err)
		require.Equal(t, 3, len(selected))
	})

	t.Run("success", func(t *testing.T) {
		s := New()
		require.NotNil(t, s)

		witnesses := []*proof.Witness{{}, {}}

		selected, err := s.Select(witnesses, 2)
		require.NoError(t, err)
		require.Equal(t, 2, len(selected))
	})

	t.Run("error", func(t *testing.T) {
		s := New()
		require.NotNil(t, s)

		selected, err := s.Select(nil, 2)
		require.Error(t, err)
		require.Empty(t, selected)
		require.True(t, errors.Is(err, orberrors.ErrWitnessesNotFound))
		require.Contains(t, err.Error(), "unable to select 2 witnesses from witness array of length 0")
	})
}
