/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscovery_RequestDiscovery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := New()

		err := d.RequestDiscovery("did")
		require.NoError(t, err)
	})
}
