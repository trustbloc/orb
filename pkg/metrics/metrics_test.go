/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	m := Get()
	require.NotNil(t, m)
	require.True(t, m == Get())

	t.Run("ActivityPub", func(t *testing.T) {
		require.NotPanics(t, func() { m.InboxHandlerTime(time.Second) })
		require.NotPanics(t, func() { m.OutboxPostTime(time.Second) })
		require.NotPanics(t, func() { m.OutboxResolveInboxesTime(time.Second) })
		require.NotPanics(t, func() { m.WriteAnchorTime(time.Second) })
		require.NotPanics(t, func() { m.ProcessWitnessedAnchoredCredentialTime(time.Second) })
		require.NotPanics(t, func() { m.AddOperationTime(time.Second) })
		require.NotPanics(t, func() { m.BatchCutTime(time.Second) })
		require.NotPanics(t, func() { m.BatchRollbackTime(time.Second) })
	})
}

func TestNewCounter(t *testing.T) {
	require.NotNil(t, newCounter("activityPub", "metric_name", "Some help"))
}

func TestNewHistogram(t *testing.T) {
	require.NotNil(t, newHistogram("activityPub", "metric_name", "Some help"))
}

func TestNewGuage(t *testing.T) {
	require.NotNil(t, newGauge("activityPub", "metric_name", "Some help"))
}
