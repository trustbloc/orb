/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package pubsub

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestContextFromMessage(t *testing.T) {
	testutil.InitTracer(t)

	ctx, span := otel.GetTracerProvider().Tracer("test").Start(context.Background(), "span1")

	msg := NewMessage(ctx, []byte("payload"))

	require.Equal(t, span.SpanContext().SpanID(), trace.SpanFromContext(ContextFromMessage(msg)).SpanContext().SpanID())
}
