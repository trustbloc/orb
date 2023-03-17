/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitialize(t *testing.T) {
	t.Run("Provider NONE", func(t *testing.T) {
		tp, err := Initialize(ProviderNone, "service1", "")
		require.NoError(t, err)
		require.Equal(t, reflect.TypeOf(&noopTracerProvider{}), reflect.TypeOf(tp))
	})

	t.Run("Provider JAEGER", func(t *testing.T) {
		tp, err := Initialize(ProviderJaeger, "service1", "")
		require.NoError(t, err)
		require.NotNil(t, tp)
		require.NotPanics(t, tp.Start)
		require.NotPanics(t, tp.Stop)

		require.NotNil(t, Tracer("subsystem1"))
	})

	t.Run("Unsupported provider", func(t *testing.T) {
		tp, err := Initialize("unsupported", "service1", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported tracing provider")
		require.Nil(t, tp)
	})
}

func TestAttributes(t *testing.T) {
	const (
		messageUUID  = "scsdcsdcsd"
		activityID   = "activity1"
		activityType = "Create"
		messageType  = "deliver"
		eventURI     = "https://localhost/event"
		suffix       = "scsdcsdcsd"
	)

	require.Equal(t, messageUUID, MessageUUIDAttribute(messageUUID).Value.AsString())
	require.Equal(t, activityID, ActivityIDAttribute(activityID).Value.AsString())
	require.Equal(t, activityType, ActivityTypeAttribute(activityType).Value.AsString())
	require.Equal(t, messageType, OutboxMessageTypeAttribute(messageType).Value.AsString())
	require.Equal(t, eventURI, AnchorEventURIAttribute(eventURI).Value.AsString())
	require.Equal(t, suffix, DIDSuffixAttribute(suffix).Value.AsString())
}

func TestSpan(t *testing.T) {
	tp, err := Initialize(ProviderJaeger, "service1", "")
	require.NoError(t, err)
	require.NotNil(t, tp)

	tracer := Tracer("subsystem1")
	require.NotNil(t, tracer)

	t.Run("Span not started", func(t *testing.T) {
		span := NewSpan(tracer, context.Background())
		require.NotNil(t, span)

		require.NotPanics(t, func() {
			span.End()
		})
	})

	t.Run("Span started", func(t *testing.T) {
		span := NewSpan(tracer, context.Background())
		require.NotNil(t, span)

		ctx := span.Start("span1")
		require.NotNil(t, ctx)

		ctx2 := span.Start("span1")
		require.Equal(t, ctx, ctx2)

		require.NotPanics(t, func() {
			span.End()
		})
	})
}
