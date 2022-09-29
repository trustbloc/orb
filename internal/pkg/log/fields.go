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
	FieldURI                    = "uri"
	FieldURIs                   = "uris"
	FieldSenderURL              = "sender"
	FieldConfig                 = "config"
	FieldServiceName            = "service"
	FieldServiceIRI             = "service-iri"
	FieldServiceEndpoint        = "service-endpoint"
	FieldActorID                = "actor-id"
	FieldActivityType           = "activity-type"
	FieldActivityID             = "activity-id"
	FieldMessageID              = "message-id"
	FieldData                   = "data"
	FieldRequestURL             = "request-url"
	FieldRequestHeaders         = "request-headers"
	FieldRequestBody            = "request-body"
	FieldResponse               = "response"
	FieldSize                   = "size"
	FieldCacheExpiration        = "cache-expiration"
	FieldTarget                 = "target"
	FieldQueue                  = "queue"
	FieldHTTPStatus             = "http-status"
	FieldParameter              = "parameter"
	FieldAcceptListType         = "accept-list-type"
	FieldAdditions              = "additions"
	FieldDeletions              = "deletions"
	FieldReferenceType          = "reference-type"
	FieldAnchorURI              = "anchor-uri"
	FieldAnchorHash             = "anchor-hash"
	FieldAnchorEventURI         = "anchor-event-uri"
	FieldObjectIRI              = "object-iri"
	FieldReferenceIRI           = "reference"
	FieldKeyID                  = "key-id"
	FieldKeyType                = "key-type"
	FieldKeyOwner               = "key-owner"
	FieldCurrent                = "current"
	FieldNext                   = "next"
	FieldTotal                  = "total"
	FieldMinimum                = "minimum"
	FieldType                   = "type"
	FieldQuery                  = "query"
	FieldSuffix                 = "suffix"
	FieldVerifiableCredential   = "vc"
	FieldVerifiableCredentialID = "vc-id"
	FieldHashlink               = "hashlink"
	FieldParent                 = "parent"
	FieldParents                = "parents"
	FieldProof                  = "proof"
	FieldCreatedTime            = "created-time"
	FieldWitnessURI             = "witness-uri"
	FieldWitnessURIs            = "witness-uris"
	FieldWitnessPolicy          = "witness-policy"
	FieldAnchorOrigin           = "anchor-origin"
	FieldOperationType          = "operation-type"
	FieldCoreIndex              = "core-index"
)

// WithError sets the error field.
func WithError(err error) zap.Field {
	return zap.Error(err)
}

// WithMessageID sets the message-id field.
func WithMessageID(value string) zap.Field {
	return zap.String(FieldMessageID, value)
}

// WithData sets the data field.
func WithData(value []byte) zap.Field {
	return zap.String(FieldData, string(value))
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

// WithCacheExpiration sets the cache-expiration field.
func WithCacheExpiration(value time.Duration) zap.Field {
	return zap.Duration(FieldCacheExpiration, value)
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

// WithURLAdditions sets the additions field.
func WithURLAdditions(value ...*url.URL) zap.Field {
	return zap.Array(FieldAdditions, NewURLArrayMarshaller(value))
}

// WithURLDeletions sets the deletions field.
func WithURLDeletions(value ...*url.URL) zap.Field {
	return zap.Array(FieldDeletions, NewURLArrayMarshaller(value))
}

// WithReferenceType sets the reference-type field.
func WithReferenceType(value string) zap.Field {
	return zap.String(FieldReferenceType, value)
}

// WithURI sets the uri field.
func WithURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldURI, value)
}

// WithURIString sets the uri field.
func WithURIString(value string) zap.Field {
	return zap.String(FieldURI, value)
}

// WithURIs sets the uris field.
func WithURIs(value ...*url.URL) zap.Field {
	return zap.Array(FieldURIs, NewURLArrayMarshaller(value))
}

// WithSenderURL sets the sender field.
func WithSenderURL(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldSenderURL, value)
}

// WithAnchorEventURI sets the anchor-event-uri field.
func WithAnchorEventURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldAnchorEventURI, value)
}

// WithAnchorEventURIString sets the anchor-event-uri field.
func WithAnchorEventURIString(value string) zap.Field {
	return zap.String(FieldAnchorEventURI, value)
}

// WithAnchorURI sets the anchor-uri field.
func WithAnchorURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldAnchorURI, value)
}

// WithAnchorURIString sets the anchor-uri field.
func WithAnchorURIString(value string) zap.Field {
	return zap.String(FieldAnchorURI, value)
}

// WithAnchorHash sets the anchor-hash field.
func WithAnchorHash(value string) zap.Field {
	return zap.String(FieldAnchorHash, value)
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
	return zap.Int(FieldTotal, value)
}

// WithMinimum sets the minimum field.
func WithMinimum(value int) zap.Field {
	return zap.Int(FieldMinimum, value)
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

// WithSuffix sets the suffix field.
func WithSuffix(value string) zap.Field {
	return zap.String(FieldSuffix, value)
}

// WithVerifiableCredential sets the vc field.
func WithVerifiableCredential(value []byte) zap.Field {
	return zap.String(FieldVerifiableCredential, string(value))
}

// WithVerifiableCredentialID sets the vc-id field.
func WithVerifiableCredentialID(value string) zap.Field {
	return zap.String(FieldVerifiableCredentialID, value)
}

// WithHashlink sets the hashlink field.
func WithHashlink(value string) zap.Field {
	return zap.String(FieldHashlink, value)
}

// WithHashlinkURI sets the hashlink field.
func WithHashlinkURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldHashlink, value)
}

// WithParent sets the parent field.
func WithParent(value string) zap.Field {
	return zap.String(FieldParent, value)
}

// WithParentURI sets the parent field.
func WithParentURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldParent, value)
}

// WithParents sets the parents field.
func WithParents(value []string) zap.Field {
	return zap.Array(FieldParents, NewStringArrayMarshaller(value))
}

// WithProof sets the proof field.
func WithProof(value []byte) zap.Field {
	return zap.String(FieldProof, string(value))
}

// WithProofDocument sets the proof field.
func WithProofDocument(value map[string]interface{}) zap.Field {
	return zap.Inline(newJSONMarshaller(FieldProof, value))
}

// WithCreatedTime sets the created-time field.
func WithCreatedTime(value time.Time) zap.Field {
	return zap.Time(FieldCreatedTime, value)
}

// WithWitnessURI sets the witness-uri field.
func WithWitnessURI(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldWitnessURI, value)
}

// WithWitnessURIString sets the witness-uri field.
func WithWitnessURIString(value string) zap.Field {
	return zap.String(FieldWitnessURI, value)
}

// WithWitnessURIs sets the witness-uris field.
func WithWitnessURIs(value ...*url.URL) zap.Field {
	return zap.Array(FieldWitnessURIs, NewURLArrayMarshaller(value))
}

// WithWitnessURIStrings sets the witness-uris field.
func WithWitnessURIStrings(value ...string) zap.Field {
	return zap.Array(FieldWitnessURIs, NewStringArrayMarshaller(value))
}

// WithWitnessPolicy sets the witness-policy field.
func WithWitnessPolicy(value string) zap.Field {
	return zap.String(FieldWitnessPolicy, value)
}

// WithAnchorOrigin sets the anchor-origin field.
func WithAnchorOrigin(value interface{}) zap.Field {
	return zap.Any(FieldAnchorOrigin, value)
}

// WithOperationType sets the operation-type field.
func WithOperationType(value string) zap.Field {
	return zap.Any(FieldOperationType, value)
}

// WithCoreIndex sets the coreIndex field.
func WithCoreIndex(value string) zap.Field {
	return zap.Any(FieldCoreIndex, value)
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

// URLArrayMarshaller marshals an array of URLs into a log field.
type URLArrayMarshaller struct {
	urls []*url.URL
}

// NewURLArrayMarshaller returns a new URLArrayMarshaller.
func NewURLArrayMarshaller(urls []*url.URL) *URLArrayMarshaller {
	return &URLArrayMarshaller{urls: urls}
}

// MarshalLogArray marshals the array.
func (m *URLArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
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
		if err := e.AddArray(k, NewStringArrayMarshaller(values)); err != nil {
			return fmt.Errorf("marshal values: %w", err)
		}
	}

	return nil
}

// StringArrayMarshaller marshals an array of strings into a log field.
type StringArrayMarshaller struct {
	values []string
}

// NewStringArrayMarshaller returns a new StringArrayMarshaller.
func NewStringArrayMarshaller(values []string) *StringArrayMarshaller {
	return &StringArrayMarshaller{values: values}
}

// MarshalLogArray marshals the array.
func (m *StringArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, v := range m.values {
		e.AppendString(v)
	}

	return nil
}
