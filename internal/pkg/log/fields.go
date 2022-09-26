/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log Fields.
const (
	FieldURI                 = "uri"
	FieldSenderURL           = "sender"
	FieldConfig              = "config"
	FieldServiceName         = "service"
	FieldServiceIRI          = "service-iri"
	FieldServiceEndpoint     = "service-endpoint"
	FieldActorID             = "actor-id"
	FieldActivityType        = "activity-type"
	FieldActivityID          = "activity-id"
	FieldMessageID           = "message-id"
	FieldPayload             = "payload"
	FieldRequestURL          = "request-url"
	FieldRequestHeaders      = "request-headers"
	FieldRequestBody         = "request-body"
	FieldResponse            = "response"
	FieldSize                = "size"
	FieldExpiration          = "expiration"
	FieldTarget              = "target"
	FieldQueue               = "queue"
	FieldHTTPStatus          = "http-status"
	FieldParameter           = "parameter"
	FieldAcceptListType      = "accept-list-type"
	FieldAcceptListAdditions = "accept-list-additions"
	FieldAcceptListDeletions = "accept-list-deletions"
	FieldReferenceType       = "reference-type"
	FieldAnchorURI           = "anchor-uri"
	FieldAnchorEventURI      = "anchor-event-uri"
	FieldObjectIRI           = "object-iri"
	FieldReferenceIRI        = "reference"
	FieldKeyID               = "key-id"
	FieldKeyType             = "key-type"
	FieldKeyOwner            = "key-owner"
	FieldCurrent             = "current"
	FieldNext                = "next"
	FieldTotalItems          = "total"
	FieldType                = "type"
	FieldQuery               = "query"
)

// WithError sets the error field.
func WithError(err error) zap.Field {
	return zap.Error(err)
}

// WithMessageID sets the message-id field.
func WithMessageID(value string) zap.Field {
	return zap.String(FieldMessageID, value)
}

// WithPayload sets the payload field.
func WithPayload(value []byte) zap.Field {
	return zap.String(FieldPayload, string(value))
}

// WithRequestURL sets the request-url field.
func WithRequestURL(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldRequestURL, value)
}

// WithRequestURLString sets the request-url field.
func WithRequestURLString(value string) zap.Field {
	return zap.String(FieldRequestURL, value)
}

// WithRequestHeaders sets the request-headers field.
func WithRequestHeaders(value http.Header) zap.Field {
	return zap.Object(FieldRequestHeaders, newHTTPHeaderMarshaller(value))
}

// WithRequestBody sets the request-body field.
func WithRequestBody(value []byte) zap.Field {
	return zap.String(FieldRequestBody, string(value))
}

// WithResponse sets the response field.
func WithResponse(value []byte) zap.Field {
	return zap.String(FieldResponse, string(value))
}

// WithServiceName sets the service field.
func WithServiceName(value string) zap.Field {
	return zap.String(FieldServiceName, value)
}

// WithServiceIRI sets the service-iri field.
func WithServiceIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldServiceIRI, value)
}

// WithServiceEndpoint sets the service-endpoint field.
func WithServiceEndpoint(value string) zap.Field {
	return zap.String(FieldServiceEndpoint, value)
}

// WithActivityType sets the activity-type field.
func WithActivityType(value string) zap.Field {
	return zap.String(FieldActivityType, value)
}

// WithActivityID sets the activity-id field.
func WithActivityID(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldActivityID, value)
}

// WithActorIRI sets the actor-id field.
func WithActorIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldActorID, value)
}

// WithActorID sets the actor-id field.
func WithActorID(value string) zap.Field {
	return zap.String(FieldActorID, value)
}

// WithConfig sets the config field. The value of the field is
// encoded as JSON.
func WithConfig(value interface{}) zap.Field {
	return zap.Inline(newJSONMarshaller(FieldConfig, value))
}

// WithSize sets the size field.
func WithSize(value int) zap.Field {
	return zap.Int(FieldSize, value)
}

// WithExpiration sets the expiration field.
func WithExpiration(value time.Duration) zap.Field {
	return zap.Duration(FieldExpiration, value)
}

// WithTarget sets the target field.
func WithTarget(value string) zap.Field {
	return zap.String(FieldTarget, value)
}

// WithTargetIRI sets the target field.
func WithTargetIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldTarget, value)
}

// WithQueue sets the queue field.
func WithQueue(value string) zap.Field {
	return zap.String(FieldQueue, value)
}

// WithHTTPStatus sets the http-status field.
func WithHTTPStatus(value int) zap.Field {
	return zap.Int(FieldHTTPStatus, value)
}

// WithParameter sets the parameter field.
func WithParameter(value string) zap.Field {
	return zap.String(FieldParameter, value)
}

// WithAcceptListType sets the accept-list-type field.
func WithAcceptListType(value string) zap.Field {
	return zap.String(FieldAcceptListType, value)
}

// WithAcceptListAdditions sets the accept-list-additions field.
func WithAcceptListAdditions(value ...*url.URL) zap.Field {
	return zap.Array(FieldAcceptListAdditions, newURLArrayMarshaller(value))
}

// WithAcceptListDeletions sets the accept-list-deletions field.
func WithAcceptListDeletions(value ...*url.URL) zap.Field {
	return zap.Array(FieldAcceptListDeletions, newURLArrayMarshaller(value))
}

// WithReferenceType sets the reference-type field.
func WithReferenceType(value string) zap.Field {
	return zap.String(FieldReferenceType, value)
}

// WithURI sets the uri field.
func WithURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldURI, value)
}

// WithSenderURL sets the sender field.
func WithSenderURL(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldSenderURL, value)
}

// WithAnchorEventURI sets the anchor-event-uri field.
func WithAnchorEventURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldAnchorEventURI, value)
}

// WithAnchorURI sets the anchor-uri field.
func WithAnchorURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldAnchorURI, value)
}

// WithObjectIRI sets the object-iri field.
func WithObjectIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldObjectIRI, value)
}

// WithReferenceIRI sets the reference field.
func WithReferenceIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldReferenceIRI, value)
}

// WithKeyID sets the key-id field.
func WithKeyID(value string) zap.Field {
	return zap.String(FieldKeyID, value)
}

// WithKeyIRI sets the key-id field.
func WithKeyIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldKeyID, value)
}

// WithKeyOwnerIRI sets the key-owner field.
func WithKeyOwnerIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldKeyOwner, value)
}

// WithKeyType sets the key-type field.
func WithKeyType(value string) zap.Field {
	return zap.String(FieldKeyType, value)
}

// WithCurrentIRI sets the current field.
func WithCurrentIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldCurrent, value)
}

// WithNextIRI sets the next field.
func WithNextIRI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldNext, value)
}

// WithTotal sets the total field.
func WithTotal(value int) zap.Field {
	return zap.Int(FieldTotalItems, value)
}

// WithType sets the type field.
func WithType(value string) zap.Field {
	return zap.String(FieldType, value)
}

// WithQuery sets the query field. The value of the field is
// encoded as JSON.
func WithQuery(value interface{}) zap.Field {
	return zap.Inline(newJSONMarshaller(FieldQuery, value))
}

type jsonMarshaller struct {
	key string
	obj interface{}
}

func newJSONMarshaller(key string, value interface{}) *jsonMarshaller {
	return &jsonMarshaller{key: key, obj: value}
}

func (m *jsonMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	b, err := json.Marshal(m.obj)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	e.AddString(m.key, string(b))

	return nil
}

type urlArrayMarshaller struct {
	urls []*url.URL
}

func newURLArrayMarshaller(urls []*url.URL) *urlArrayMarshaller {
	return &urlArrayMarshaller{urls: urls}
}

func (m *urlArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, u := range m.urls {
		e.AppendString(u.String())
	}

	return nil
}

type httpHeaderMarshaller struct {
	headers http.Header
}

func newHTTPHeaderMarshaller(headers http.Header) *httpHeaderMarshaller {
	return &httpHeaderMarshaller{headers: headers}
}

func (m *httpHeaderMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	for k, values := range m.headers {
		if err := e.AddArray(k, newStringArrayMarshaller(values)); err != nil {
			return fmt.Errorf("marshal values: %w", err)
		}
	}

	return nil
}

type stringArrayMarshaller struct {
	values []string
}

func newStringArrayMarshaller(values []string) *stringArrayMarshaller {
	return &stringArrayMarshaller{values: values}
}

func (m *stringArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, v := range m.values {
		e.AppendString(v)
	}

	return nil
}
