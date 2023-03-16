/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package otelamqp

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("otelamqp")

const (
	messagingSystem = "rabbitmq"
)

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	PublishWithOpts(topic string, msg *message.Message, opts ...spi.Option) error
	IsConnected() bool
	Close() error
}

type PubSub struct {
	pubSub

	tracer          trace.Tracer
	propagators     propagation.TextMapPropagator
	messagingSystem string
}

func New(p pubSub) *PubSub {
	return &PubSub{
		pubSub:          p,
		messagingSystem: messagingSystem,
		tracer:          tracing.Tracer(tracing.SubsystemAMQP),
		propagators:     otel.GetTextMapPropagator(),
	}
}

func (p *PubSub) Publish(queue string, messages ...*message.Message) error {
	if len(messages) > 1 {
		logger.Warn("Tracing is supported for only one message at a time. No tracing will be performed.",
			logfields.WithTotal(len(messages)))

		return p.pubSub.Publish(queue, messages...)
	}

	if len(messages) == 0 {
		logger.Warn("No messages to publish.")

		return nil
	}

	msg := messages[0]

	span := p.startPubSpan(queue, msg)

	err := p.pubSub.Publish(queue, msg)

	p.finishSpan(span, err)

	return err
}

func (p *PubSub) PublishWithOpts(queue string, msg *message.Message, opts ...spi.Option) error {
	span := p.startPubSpan(queue, msg)

	err := p.pubSub.PublishWithOpts(queue, msg, opts...)

	p.finishSpan(span, err)

	return err
}

func (p *PubSub) startPubSpan(queue string, msg *message.Message) trace.Span {
	// If there's a span context in the message, use that as the parent context.
	carrier := NewMessageCarrier(msg)
	ctx := p.propagators.Extract(context.Background(), carrier)

	// Create a span.
	attrs := []attribute.KeyValue{
		semconv.MessagingSystem(p.messagingSystem),
		semconv.MessagingDestinationKindQueue,
		semconv.MessagingDestinationName(queue),
		semconv.MessagingMessagePayloadSizeBytes(len(msg.Payload)),
		semconv.MessagingOperationPublish,
		{Key: tracing.AttributeMessageUUID, Value: attribute.StringValue(msg.UUID)},
	}

	opts := []trace.SpanStartOption{
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindProducer),
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("%s publish", queue), opts...)

	// Inject current span context, so consumers can use it to propagate span.
	p.propagators.Inject(ctx, carrier)

	return span
}

func (p *PubSub) startSubSpan(queue string, msg *message.Message) trace.Span {
	// If there's a span context in the message, use that as the parent context.
	carrier := NewMessageCarrier(msg)
	ctx := p.propagators.Extract(context.Background(), carrier)

	// Create a span.
	attrs := []attribute.KeyValue{
		semconv.MessagingSystem(p.messagingSystem),
		semconv.MessagingDestinationKindQueue,
		semconv.MessagingDestinationName(queue),
		semconv.MessagingMessagePayloadSizeBytes(len(msg.Payload)),
		semconv.MessagingOperationPublish,
		tracing.MessageUUIDAttribute(msg.UUID),
	}

	opts := []trace.SpanStartOption{
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindProducer),
	}

	ctx, span := p.tracer.Start(ctx, fmt.Sprintf("%s receive", queue), opts...)

	// Inject current span context, so consumers can use it to propagate span.
	p.propagators.Inject(ctx, carrier)

	return span
}

func (p *PubSub) finishSpan(span trace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
	}

	span.End()
}

func (p *PubSub) Subscribe(ctx context.Context, queue string) (<-chan *message.Message, error) {
	msgChan, err := p.pubSub.Subscribe(ctx, queue)
	if err != nil {
		return nil, err
	}

	subChan := make(chan *message.Message)

	go p.listen(queue, msgChan, subChan)

	return subChan, nil
}

func (p *PubSub) SubscribeWithOpts(ctx context.Context, queue string, opts ...spi.Option) (<-chan *message.Message, error) {
	msgChan, err := p.pubSub.SubscribeWithOpts(ctx, queue, opts...)
	if err != nil {
		return nil, err
	}

	subChan := make(chan *message.Message)

	go p.listen(queue, msgChan, subChan)

	return subChan, nil
}

func (p *PubSub) listen(queue string, msgChan <-chan *message.Message, subChan chan *message.Message) {
	for msg := range msgChan {
		span := p.startSubSpan(queue, msg)

		// Send messages back to user.
		subChan <- msg

		span.End()
	}
}

var _ propagation.TextMapCarrier = (*MessageCarrier)(nil)

// MessageCarrier injects and extracts traces from a Message.
type MessageCarrier struct {
	msg *message.Message
}

// NewMessageCarrier creates a new MessageCarrier.
func NewMessageCarrier(msg *message.Message) *MessageCarrier {
	return &MessageCarrier{msg: msg}
}

// Get retrieves a single value for a given key.
func (c *MessageCarrier) Get(key string) string {
	return c.msg.Metadata.Get(key)
}

// Set sets a header.
func (c *MessageCarrier) Set(key, val string) {
	c.msg.Metadata.Set(key, val)
}

// Keys returns a slice of all key identifiers in the carrier.
func (c *MessageCarrier) Keys() []string {
	if len(c.msg.Metadata) == 0 {
		return nil
	}

	out := make([]string, len(c.msg.Metadata))

	i := 0

	for key := range c.msg.Metadata {
		out[i] = key
		i++
	}

	return out
}
