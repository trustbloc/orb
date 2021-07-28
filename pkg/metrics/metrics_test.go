/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
		require.NotPanics(t, func() { m.WitnessAnchorCredentialTime(time.Second) })
		require.NotPanics(t, func() { m.ProcessWitnessedAnchorCredentialTime(time.Second) })
		require.NotPanics(t, func() { m.AddOperationTime(time.Second) })
		require.NotPanics(t, func() { m.BatchCutTime(time.Second) })
		require.NotPanics(t, func() { m.BatchRollbackTime(time.Second) })
		require.NotPanics(t, func() { m.BatchAckTime(time.Second) })
		require.NotPanics(t, func() { m.BatchNackTime(time.Second) })
		require.NotPanics(t, func() { m.ProcessAnchorTime(time.Second) })
		require.NotPanics(t, func() { m.ProcessDIDTime(time.Second) })
		require.NotPanics(t, func() { m.CASWriteTime(time.Second) })
		require.NotPanics(t, func() { m.CASResolveTime(time.Second) })
		require.NotPanics(t, func() { m.DocumentCreateUpdateTime(time.Second) })
		require.NotPanics(t, func() { m.DocumentResolveTime(time.Second) })
		require.NotPanics(t, func() { m.InboxIncrementActivityCount("Create") })
		require.NotPanics(t, func() { m.OutboxIncrementActivityCount("Create") })
	})
}

func TestNewCounter(t *testing.T) {
	labels := prometheus.Labels{"type": "create"}

	require.NotNil(t, newCounter("activityPub", "metric_name", "Some help", labels))
}

func TestNewHistogram(t *testing.T) {
	require.NotNil(t, newHistogram("activityPub", "metric_name", "Some help"))
}

func TestNewGuage(t *testing.T) {
	require.NotNil(t, newGauge("activityPub", "metric_name", "Some help"))
}
