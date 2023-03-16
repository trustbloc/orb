/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"context"
	"fmt"
	"os"

	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.New("tracing")

const instrumentationVersion = "1.0.0"

// Subsystem defines an Orb subsystem.
type Subsystem string

// Subsystems.
const (
	SubsystemActivityPub    Subsystem = "activitypub"
	SubsystemAnchor         Subsystem = "anchor"
	SubsystemDocument       Subsystem = "document"
	SubsystemOperationQueue Subsystem = "context/opqueue"
	SubsystemAMQP           Subsystem = "pubsub/amqp"
)

// Tracing attributes.
const (
	AttributeMessageUUID       attribute.Key = "orb.messageUUID"
	AttributeActivityID        attribute.Key = "orb.activityID"
	AttributeActivityType      attribute.Key = "orb.activityType"
	AttributeOutboxMessageType attribute.Key = "orb.outboxMessageType"
	AttributeAnchorEventURI    attribute.Key = "orb.anchorEventURI"
	AttributeDIDSuffix         attribute.Key = "orb.didSuffix"
)

const tracerRootName = "github.com/trustbloc/orb"

// ProviderType specifies the type of the tracer provider.
type ProviderType = string

const (
	// ProviderNone indicates that tracing is disabled.
	ProviderNone ProviderType = ""
	// ProviderJaeger indicates that tracing data should be in Jaeger format.
	ProviderJaeger ProviderType = "JAEGER"
)

// Provider creates tracers.
type Provider interface {
	trace.TracerProvider

	Start()
	Stop()
}

// Initialize creates and registers globally a new tracer Provider.
func Initialize(provider, serviceName, url string) (Provider, error) {
	if provider == ProviderNone {
		tp := newNoopTracerProvider()

		otel.SetTracerProvider(tp)

		return tp, nil
	}

	var tp *tracesdk.TracerProvider

	switch provider {
	case ProviderJaeger:
		var err error

		tp, err = newJaegerTracerProvider(serviceName, url)
		if err != nil {
			return nil, fmt.Errorf("create new tracer provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported tracing provider: %s", provider)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Register the TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(tp)

	logger.Info("Enabled tracing", logfields.WithTracingProvider(provider), logfields.WithServiceName(serviceName), log.WithURL(url))

	return &otelTracerProvider{TracerProvider: tp}, nil
}

// Tracer returns a tracer for the given subsystem.
func Tracer(subsystem Subsystem) trace.Tracer {
	return otel.GetTracerProvider().Tracer(fmt.Sprintf("%s/pkg/%s", tracerRootName, subsystem),
		trace.WithInstrumentationVersion(instrumentationVersion))
}

// MessageUUIDAttribute returns the orb.messageUUID tracing attribute.
func MessageUUIDAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeMessageUUID, Value: attribute.StringValue(value)}
}

// ActivityIDAttribute returns the orb.activityID tracing attribute.
func ActivityIDAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeActivityID, Value: attribute.StringValue(value)}
}

// ActivityTypeAttribute returns the orb.activityType tracing attribute.
func ActivityTypeAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeActivityType, Value: attribute.StringValue(value)}
}

// OutboxMessageTypeAttribute returns the orb.outboxMessageType tracing attribute.
func OutboxMessageTypeAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeOutboxMessageType, Value: attribute.StringValue(value)}
}

// AnchorEventURIAttribute returns the orb.anchorEventURI tracing attribute.
func AnchorEventURIAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeAnchorEventURI, Value: attribute.StringValue(value)}
}

// DIDSuffixAttribute returns the orb.didSuffix tracing attribute.
func DIDSuffixAttribute(value string) attribute.KeyValue {
	return attribute.KeyValue{Key: AttributeDIDSuffix, Value: attribute.StringValue(value)}
}

// Span is a wrapper around a trace.Span that ensures it is started only once
// and ended only if it was started.
type Span struct {
	span   trace.Span
	tracer trace.Tracer
	ctx    context.Context
}

// NewSpan returns a Span wrapper.
func NewSpan(tracer trace.Tracer, ctx context.Context) *Span {
	return &Span{tracer: tracer, ctx: ctx}
}

// Start starts a span if it hasn't already been started.
func (s *Span) Start(name string, opts ...trace.SpanStartOption) context.Context {
	if s.span != nil {
		return s.ctx
	}

	s.ctx, s.span = s.tracer.Start(s.ctx, name, opts...)

	return s.ctx
}

// End ends the span if it had been started.
func (s *Span) End(opts ...trace.SpanEndOption) {
	if s.span != nil {
		s.span.End(opts...)
	}
}

// newJaegerTracerProvider returns an OpenTelemetry Provider configured to use
// the Jaeger exporter that will send spans to the provided url. The returned
// Provider will also use a Resource configured with all the information
// about the application.
func newJaegerTracerProvider(serviceName, url string) (*tracesdk.TracerProvider, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(url)))
	if err != nil {
		return nil, fmt.Errorf("create jaeger collector: %w", err)
	}

	return tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exp),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.ProcessPIDKey.Int(os.Getpid()),
		)),
	), nil
}

type otelTracerProvider struct {
	*tracesdk.TracerProvider
}

func (tp *otelTracerProvider) Start() {}

func (tp *otelTracerProvider) Stop() {
	if err := tp.TracerProvider.Shutdown(context.Background()); err != nil {
		logger.Warn("Error shutting down tracer provider", log.WithError(err))
	}
}

type noopTracerProvider struct {
	*lifecycle.Lifecycle
	trace.TracerProvider
}

func newNoopTracerProvider() *noopTracerProvider {
	return &noopTracerProvider{
		Lifecycle:      lifecycle.New("noopTracerProvider"),
		TracerProvider: trace.NewNoopTracerProvider(),
	}
}
