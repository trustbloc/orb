/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("success - default policy (100% batch and 100% system witnesses)", func(t *testing.T) {
		wp, err := Parse("")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 0, wp.MinNumberBatch)
		require.Equal(t, 0, wp.MinNumberSystem)
		require.Equal(t, 100, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, false, wp.LogRequired)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))

		require.NotEmpty(t, wp.String())
	})

	t.Run("error - rule not supported ", func(t *testing.T) {
		wp, err := Parse("Test(2,3)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "rule not supported: Test(2,3)")
	})
}

func TestParse_OutOf(t *testing.T) {
	t.Run("success - OutOf policy for system", func(t *testing.T) {
		wp, err := Parse("OutOf(2,system)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 0, wp.MinNumberBatch)
		require.Equal(t, 2, wp.MinNumberSystem)
		require.Equal(t, 100, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))
	})

	t.Run("success - OutOf policy for batch", func(t *testing.T) {
		wp, err := Parse("OutOf(2,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 2, wp.MinNumberBatch)
		require.Equal(t, 0, wp.MinNumberSystem)
		require.Equal(t, 100, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))
	})

	t.Run("success - OutOf policy for batch", func(t *testing.T) {
		wp, err := Parse("OutOf(3,system) AND OutOf(1,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 1, wp.MinNumberBatch)
		require.Equal(t, 3, wp.MinNumberSystem)
		require.Equal(t, 100, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))
	})

	t.Run("error - first argument for OutOf policy must be an integer", func(t *testing.T) {
		wp, err := Parse("OutOf(a,system)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer")
	})

	t.Run("error - role 'invalid' not supported for OutOf policy", func(t *testing.T) {
		wp, err := Parse("OutOf(2,invalid)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "role 'invalid' not supported for OutOf policy")
	})

	t.Run("error - expected 2 but got 3 arguments for OutOf", func(t *testing.T) {
		wp, err := Parse("OutOf(2,system,other)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "expected 2 but got 3 arguments for OutOf")
	})
}

func TestParse_MinPercent(t *testing.T) {
	t.Run("success - MinPercent policy for batch", func(t *testing.T) {
		wp, err := Parse("MinPercent(70,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 0, wp.MinNumberBatch)
		require.Equal(t, 0, wp.MinNumberSystem)
		require.Equal(t, 70, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))
	})

	t.Run("success - MinPercent policy for batch and system", func(t *testing.T) {
		wp, err := Parse("MinPercent(30,system) OR MinPercent(70,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 0, wp.MinNumberBatch)
		require.Equal(t, 0, wp.MinNumberSystem)
		require.Equal(t, 70, wp.MinPercentBatch)
		require.Equal(t, 30, wp.MinPercentSystem)
		require.Equal(t, or(true, false), wp.OperatorFnc(true, false))
	})

	t.Run("error - role 'invalid' not supported for MinPercent policy", func(t *testing.T) {
		wp, err := Parse("MinPercent(70,invalid)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "role 'invalid' not supported for MinPercent policy")
	})

	t.Run("error - first argument not an integer", func(t *testing.T) {
		wp, err := Parse("MinPercent(invalid,batch)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer between 0 and 100: strconv.Atoi")
	})

	t.Run("error - first argument for OutOf policy must be an integer between 0 and 100", func(t *testing.T) {
		wp, err := Parse("MinPercent(150,batch)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer between 0 and 100")
	})

	t.Run("error - expected 2 but got 3 arguments for MinPercent", func(t *testing.T) {
		wp, err := Parse("MinPercent(20,system,other)")
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "expected 2 but got 3 arguments for MinPercent")
	})
}

func TestParse_LogRequired(t *testing.T) {
	t.Run("success - log required", func(t *testing.T) {
		wp, err := Parse("LogRequired")
		require.NoError(t, err)
		require.NotNil(t, wp)

		require.Equal(t, 0, wp.MinNumberBatch)
		require.Equal(t, 0, wp.MinNumberSystem)
		require.Equal(t, 100, wp.MinPercentBatch)
		require.Equal(t, 100, wp.MinPercentSystem)
		require.Equal(t, true, wp.LogRequired)
		require.Equal(t, and(true, false), wp.OperatorFnc(true, false))
	})
}
