/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchortime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
)

func TestValidator_Validate(t *testing.T) {
	const maxDelta = 10 * 60
	v := New(maxDelta)

	now := time.Now().Unix()

	const testDelta = 5 * 60

	t.Run("success - no anchoring times specified", func(t *testing.T) {
		err := v.Validate(0, 0)
		require.NoError(t, err)
	})

	t.Run("success - anchoring times specified", func(t *testing.T) {
		err := v.Validate(now-testDelta, now+testDelta)
		require.NoError(t, err)
	})

	t.Run("success - anchor until time is not specified (protocol op delta is used to calc until)", func(t *testing.T) {
		err := v.Validate(now-testDelta, 0)
		require.NoError(t, err)
	})

	t.Run("error - anchor until time is not specified (delta is zero hence operation expired error)", func(t *testing.T) {
		v2 := New(0)
		err := v2.Validate(now-testDelta, 0)
		require.Equal(t, err, operationparser.ErrOperationExpired)
	})

	t.Run("error - anchor from time is greater then anchoring time", func(t *testing.T) {
		err := v.Validate(now+testDelta, now+testDelta)
		require.Error(t, err)
		require.Equal(t, err, operationparser.ErrOperationEarly)
	})

	t.Run("error - anchor until time is less then anchoring time", func(t *testing.T) {
		err := v.Validate(now-testDelta, now-testDelta)
		require.Error(t, err)
		require.Equal(t, err, operationparser.ErrOperationExpired)
	})
}
