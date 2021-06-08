/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/discovery/did/mocks"
)

//go:generate counterfeiter -o ../mocks/didPublisher.gen.go --fake-name DIDPublisher . didPublisher

func TestDiscovery_RequestDiscovery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := New(&mocks.DIDPublisher{})

		err := d.RequestDiscovery("did")
		require.NoError(t, err)
	})
}
