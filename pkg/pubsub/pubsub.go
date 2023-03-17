/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package pubsub

import (
	"context"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"go.opentelemetry.io/otel"

	"github.com/trustbloc/orb/pkg/observability/tracing/otelamqp"
)

// ContextFromMessage returns a new Context which may include OpenTelemetry tracing data.
func ContextFromMessage(msg *message.Message) context.Context {
	return otel.GetTextMapPropagator().Extract(context.Background(), otelamqp.NewMessageCarrier(msg))
}

// NewMessage creates a new message which may include OpenTelemetry tracing data in the header.
func NewMessage(ctx context.Context, payload []byte) *message.Message {
	msg := message.NewMessage(watermill.NewUUID(), payload)

	InjectContext(ctx, msg)

	return msg
}

// InjectContext adds OpenTelemetry tracing data to the message header (if available).
func InjectContext(ctx context.Context, msg *message.Message) {
	otel.GetTextMapPropagator().Inject(ctx, otelamqp.NewMessageCarrier(msg))
}
