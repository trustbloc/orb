/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchororigin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidator_Validate(t *testing.T) {
	v := New([]string{"*"})

	t.Run("error - no anchor origin specified", func(t *testing.T) {
		err := v.Validate(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor origin must be specified")
	})

	t.Run("success - allow all origins", func(t *testing.T) {
		err := v.Validate("test")
		require.NoError(t, err)
	})

	t.Run("success - allowed origins specified", func(t *testing.T) {
		validator := New([]string{"allowed"})
		err := validator.Validate("allowed")
		require.NoError(t, err)
	})

	t.Run("error - origin not in the allowed list", func(t *testing.T) {
		validator := New([]string{"allowed"})
		err := validator.Validate("not-allowed")
		require.Error(t, err)
		require.Contains(t, err.Error(), "origin not-allowed is not supported")
	})
}
