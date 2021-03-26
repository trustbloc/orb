/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscovery_RequestDiscovery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		didCh := make(chan []string, 100)
		d := New(didCh)

		err := d.RequestDiscovery("did")
		require.NoError(t, err)
	})
}
