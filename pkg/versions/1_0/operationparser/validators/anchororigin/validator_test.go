/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchororigin

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

func TestValidator_Validate(t *testing.T) {
	v := New(mocks.NewAllowedOriginsStore().FromString("*"), time.Second)

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
		validator := New(mocks.NewAllowedOriginsStore().FromString("allowed"), time.Second)
		err := validator.Validate("allowed")
		require.NoError(t, err)
	})

	t.Run("error - origin not in the allowed list", func(t *testing.T) {
		validator := New(mocks.NewAllowedOriginsStore().FromString("allowed"), time.Second)
		err := validator.Validate("not-allowed")
		require.Error(t, err)
		require.Contains(t, err.Error(), "origin not-allowed is not supported")
	})
}

func TestValidator_ValidateError(t *testing.T) {
	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		v := New(mocks.NewAllowedOriginsStore().FromString("*").WithError(errExpected), time.Second)

		err := v.Validate("test")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}
