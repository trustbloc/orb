/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

func TestFactory_Create(t *testing.T) {
	f := New()
	require.NotNil(t, f)

	casClient := &mocks.CasClient{}

	t.Run("success", func(t *testing.T) {
		pv, err := f.Create("test", casClient, &config.Sidetree{})
		require.NoError(t, err)
		require.NotNil(t, pv)
	})
}
