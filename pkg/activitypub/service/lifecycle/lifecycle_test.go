/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

func TestLifecycle(t *testing.T) {
	started := false
	stopped := false

	lc := New(
		"service1",
		WithStart(func() {
			started = true
		}),
		WithStop(func() {
			stopped = true
		}),
	)
	require.NotNil(t, lc)

	require.Equal(t, spi.StateNotStarted, lc.State())

	lc.Start()
	require.True(t, started)
	require.Equal(t, spi.StateStarted, lc.State())

	require.NotPanics(t, lc.Start)

	lc.Stop()
	require.True(t, stopped)
	require.Equal(t, spi.StateStopped, lc.State())

	require.NotPanics(t, lc.Stop)
}
