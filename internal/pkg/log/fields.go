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
	FieldURL                    = "url"
	FieldSenderURL              = "sender"
	FieldConfig                 = "config"
	FieldServiceName            = "service"
	FieldServiceIRI             = "serviceIri"
	FieldServiceEndpoint        = "serviceEndpoint"
	FieldActorID                = "actorId"
	FieldOriginActorID          = "originActorId"
	FieldActivityType           = "activityType"
	FieldActivityID             = "activityId"
	FieldMessageID              = "messageId"
	FieldData                   = "data"
	FieldMetadata               = "metadata"
	FieldRequestURL             = "requestUrl"
	FieldRequestHeaders         = "requestHeaders"
	FieldRequestBody            = "requestBody"
	FieldResponse               = "response"
	FieldSize                   = "size"
	FieldMaxSize                = "maxSize"
	FieldCacheExpiration        = "cacheExpiration"
	FieldTarget                 = "target"
	FieldTargets                = "targets"
	FieldHTTPMethod             = "httpMethod"
	FieldParameter              = "parameter"
	FieldParameters             = "parameters"
	FieldAcceptListType         = "acceptListType"
	FieldAdditions              = "additions"
	FieldDeletions              = "deletions"
	FieldReferenceType          = "referenceType"
	FieldAnchorURI              = "anchorUri"
	FieldAnchorURIs             = "anchorURIs"
	FieldAnchorHash             = "anchorHash"
	FieldAnchorEventURI         = "anchorEventUri"
	FieldObjectIRI              = "objectIri"
	FieldReferenceIRI           = "reference"
	FieldKeyID                  = "keyId"
	FieldKeyType                = "keyType"
	FieldKeyOwner               = "keyOwner"
	FieldCurrent                = "current"
	FieldNext                   = "next"
	FieldTotal                  = "total"
	FieldMinimum                = "minimum"
	FieldType                   = "type"
	FieldQuery                  = "query"
	FieldSuffix                 = "suffix"
	FieldSuffixes               = "suffixes"
	FieldVerifiableCredential   = "vc"
	FieldVerifiableCredentialID = "vcId"
	FieldHash                   = "hash"
	FieldHashlink               = "hashlink"
	FieldLocalHashlink          = "localHashlink"
	FieldParent                 = "parent"
	FieldParents                = "parents"
	FieldProof                  = "proof"
	FieldCreatedTime            = "createdTime"
	FieldWitnessURI             = "witnessUri"
	FieldWitnessURIs            = "witnessURIs"
	FieldWitnessPolicy          = "witnessPolicy"
	FieldAnchorOrigin           = "anchorOrigin"
	FieldAnchorOriginEndpoint   = "anchorOriginEndpoint"
	FieldOperationType          = "operationType"
	FieldOperation              = "operation"
	FieldCoreIndex              = "coreIndex"
	FieldKey                    = "key"
	FieldValue                  = "value"
	FieldCID                    = "cid"
	FieldResolvedCID            = "resolvedCid"
	FieldAnchorCID              = "anchorCid"
	FieldCIDVersion             = "cidVersion"
	FieldMultihash              = "multihash"
	FieldCASData                = "casData"
	FieldDomain                 = "domain"
	FieldLink                   = "link"
	FieldLinks                  = "links"
	FieldTaskMgrInstanceID      = "taskMgrInstanceId"
	FieldTaskID                 = "taskId"
	FieldRetries                = "retries"
	FieldMaxRetries             = "maxRetries"
	FieldSubscriberPoolSize     = "subscriberPoolSize"
	FieldTaskMonitorInterval    = "taskMonitorInterval"
	FieldTaskExpiration         = "taskExpiration"
	FieldDeliveryDelay          = "deliveryDelay"
	FieldOperationID            = "operationId"
	FieldPermitHolder           = "permitHolder"
	FieldTimeSinceLastUpdate    = "timeSinceLastUpdate"
	FieldGenesisTime            = "genesisTime"
	FieldSidetreeProtocol       = "sidetreeProtocol"
	FieldSidetreeTxn            = "sidetreeTxn"
	FieldDID                    = "did"
	FieldHRef                   = "href"
	FieldID                     = "id"
	FieldResource               = "resource"
	FieldResolutionResult       = "resolutionResult"
	FieldResolutionModel        = "resolutionModel"
	FieldResolutionEndpoints    = "resolutionEndpoints"
	FieldAuthToken              = "authToken"
	FieldAuthTokens             = "authTokens"
	FieldAddress                = "address"
	FieldAttributedTo           = "attributedTo"
	FieldAnchorLink             = "anchorLink"
	FieldAnchorLinkset          = "anchorLinkset"
	FieldVersion                = "version"
	FieldDeliveryAttempts       = "deliveryAttempts"
	FieldProperty               = "property"
	FieldStorageName            = "storeName"
	FieldIssuer                 = "issuer"
	FieldStatus                 = "status"
	FieldLogURL                 = "logURL"
	FieldNamespace              = "namespace"
	FieldCanonicalRef           = "canonicalRef"
	FieldAnchorString           = "anchorString"
	FieldJRD                    = "jrd"
	FieldBackoff                = "backoff"
	FieldTimeout                = "timeout"
	FieldMaxTime                = "maxTime"
	FieldLogMonitor             = "logMonitor"
	FieldLogMonitors            = "logMonitors"
	FieldIndex                  = "index"
	FieldFromIndex              = "fromIndex"
	FieldToIndex                = "toIndex"
	FieldSource                 = "source"
	FieldAge                    = "age"
	FieldMinAge                 = "minAge"
	FieldLogSpec                = "logSpec"
	FieldTracingProvider        = "tracingProvider"
	FieldMaxOperationsToRepost  = "maxOperationsToRepost"
)

// WithMessageID sets the message-id field.
func WithMessageID(value string) zap.Field {
	return zap.String(FieldMessageID, value)
}

// WithData sets the data field.
func WithData(value []byte) zap.Field {
	return zap.String(FieldData, string(value))
}

// WithMetadata sets the metadata field.
func WithMetadata(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldMetadata, value))
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
	return zap.Inline(NewObjectMarshaller(FieldRequestHeaders, value))
}

// WithRequestBody sets the request-body field.
func WithRequestBody(value []byte) zap.Field {
	return zap.String(FieldRequestBody, string(value))
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

// WithOriginActorID sets the origin-actor-id field.
func WithOriginActorID(value string) zap.Field {
	return zap.String(FieldOriginActorID, value)
}

// WithConfig sets the config field. The value of the field is
// encoded as JSON.
func WithConfig(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldConfig, value))
}

// WithSize sets the size field.
func WithSize(value int) zap.Field {
	return zap.Int(FieldSize, value)
}

// WithSizeUint64 sets the size field.
func WithSizeUint64(value uint64) zap.Field {
	return zap.Uint64(FieldSize, value)
}

// WithMaxSize sets the max-size field.
func WithMaxSize(value int) zap.Field {
	return zap.Int(FieldMaxSize, value)
}

// WithMaxSizeUInt64 sets the max-size field.
func WithMaxSizeUInt64(value uint64) zap.Field {
	return zap.Uint64(FieldMaxSize, value)
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

// WithTargetIRIs sets the targets field.
func WithTargetIRIs(value ...*url.URL) zap.Field {
	return zap.Array(FieldTargets, NewURLArrayMarshaller(value))
}

// WithHTTPMethod sets the http-method field.
func WithHTTPMethod(value string) zap.Field {
	return zap.String(FieldHTTPMethod, value)
}

// WithParameter sets the parameter field.
func WithParameter(value string) zap.Field {
	return zap.String(FieldParameter, value)
}

// WithParameters sets the parameters field.
func WithParameters(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldParameters, value))
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

// WithURL sets the url field.
func WithURL(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldURL, value)
}

// WithURLString sets the url field.
func WithURLString(value string) zap.Field {
	return zap.String(FieldURL, value)
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

// WithAnchorURIStrings sets the anchor-uris field.
func WithAnchorURIStrings(value ...string) zap.Field {
	return zap.Array(FieldAnchorURIs, NewStringArrayMarshaller(value))
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
	return zap.Inline(NewObjectMarshaller(FieldQuery, value))
}

// WithSuffix sets the suffix field.
func WithSuffix(value string) zap.Field {
	return zap.String(FieldSuffix, value)
}

// WithSuffixes sets the suffixes field.
func WithSuffixes(value ...string) zap.Field {
	return zap.Array(FieldSuffixes, NewStringArrayMarshaller(value))
}

// WithVerifiableCredential sets the vc field.
func WithVerifiableCredential(value []byte) zap.Field {
	return zap.String(FieldVerifiableCredential, string(value))
}

// WithVerifiableCredentialID sets the vc-id field.
func WithVerifiableCredentialID(value string) zap.Field {
	return zap.String(FieldVerifiableCredentialID, value)
}

// WithHash sets the hash field.
func WithHash(value string) zap.Field {
	return zap.String(FieldHash, value)
}

// WithHashlink sets the hashlink field.
func WithHashlink(value string) zap.Field {
	return zap.String(FieldHashlink, value)
}

// WithLocalHashlink sets the local-hashlink field.
func WithLocalHashlink(value string) zap.Field {
	return zap.String(FieldLocalHashlink, value)
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

// WithAnchorOriginEndpoint sets the anchor-origin-endpoint field.
func WithAnchorOriginEndpoint(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldAnchorOriginEndpoint, value))
}

// WithOperationType sets the operation-type field.
func WithOperationType(value string) zap.Field {
	return zap.Any(FieldOperationType, value)
}

// WithOperation sets the operation field.
func WithOperation(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldOperation, value))
}

// WithCoreIndex sets the coreIndex field.
func WithCoreIndex(value string) zap.Field {
	return zap.Any(FieldCoreIndex, value)
}

// WithKey sets the key field.
func WithKey(value string) zap.Field {
	return zap.String(FieldKey, value)
}

// WithValue sets the value field.
func WithValue(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldValue, value))
}

// WithCID sets the cid field.
func WithCID(value string) zap.Field {
	return zap.String(FieldCID, value)
}

// WithResolvedCID sets the resolved-cid field.
func WithResolvedCID(value string) zap.Field {
	return zap.String(FieldResolvedCID, value)
}

// WithAnchorCID sets the anchor-cid field.
func WithAnchorCID(value string) zap.Field {
	return zap.String(FieldAnchorCID, value)
}

// WithCIDVersion sets the cid-version field.
func WithCIDVersion(value int) zap.Field {
	return zap.Int(FieldCIDVersion, value)
}

// WithMultihash sets the multihash field.
func WithMultihash(value string) zap.Field {
	return zap.String(FieldMultihash, value)
}

// WithCASData sets the cas-data field.
func WithCASData(value []byte) zap.Field {
	return zap.Binary(FieldCASData, value)
}

// WithDomain sets the domain field.
func WithDomain(value string) zap.Field {
	return zap.String(FieldDomain, value)
}

// WithLink sets the link field.
func WithLink(value string) zap.Field {
	return zap.String(FieldLink, value)
}

// WithLinks sets the links field.
func WithLinks(value ...string) zap.Field {
	return zap.Array(FieldLinks, NewStringArrayMarshaller(value))
}

// WithTaskMgrInstanceID sets the task-mgr-instance field.
func WithTaskMgrInstanceID(value string) zap.Field {
	return zap.String(FieldTaskMgrInstanceID, value)
}

// WithTaskID sets the task-id field.
func WithTaskID(value string) zap.Field {
	return zap.String(FieldTaskID, value)
}

// WithRetries sets the retries field.
func WithRetries(value int) zap.Field {
	return zap.Int(FieldRetries, value)
}

// WithMaxRetries sets the max-retries field.
func WithMaxRetries(value int) zap.Field {
	return zap.Int(FieldMaxRetries, value)
}

// WithSubscriberPoolSize sets the subscriber-pool-size field.
func WithSubscriberPoolSize(value int) zap.Field {
	return zap.Int(FieldSubscriberPoolSize, value)
}

// WithTaskMonitorInterval sets the task-monitor-interval field.
func WithTaskMonitorInterval(value time.Duration) zap.Field {
	return zap.Duration(FieldTaskMonitorInterval, value)
}

// WithTaskExpiration sets the task-expiration field.
func WithTaskExpiration(value time.Duration) zap.Field {
	return zap.Duration(FieldTaskExpiration, value)
}

// WithDeliveryDelay sets the delivery-delay field.
func WithDeliveryDelay(value time.Duration) zap.Field {
	return zap.Duration(FieldDeliveryDelay, value)
}

// WithOperationID sets the operation-id field.
func WithOperationID(value string) zap.Field {
	return zap.String(FieldOperationID, value)
}

// WithPermitHolder sets the permit-holder field.
func WithPermitHolder(value string) zap.Field {
	return zap.String(FieldPermitHolder, value)
}

// WithTimeSinceLastUpdate sets the time-since-last-update field.
func WithTimeSinceLastUpdate(value time.Duration) zap.Field {
	return zap.Duration(FieldTimeSinceLastUpdate, value)
}

// WithGenesisTime sets the genesis-time field.
func WithGenesisTime(value uint64) zap.Field {
	return zap.Uint64(FieldGenesisTime, value)
}

// WithSidetreeProtocol sets the sidetree-protocol field.
func WithSidetreeProtocol(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldSidetreeProtocol, value))
}

// WithSidetreeTxn sets the sidetree-txn field.
func WithSidetreeTxn(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldSidetreeTxn, value))
}

// WithDID sets the did field.
func WithDID(value string) zap.Field {
	return zap.String(FieldDID, value)
}

// WithHRef sets the href field.
func WithHRef(value string) zap.Field {
	return zap.String(FieldHRef, value)
}

// WithID sets the id field.
func WithID(value string) zap.Field {
	return zap.String(FieldID, value)
}

// WithResource sets the resource field.
func WithResource(value string) zap.Field {
	return zap.String(FieldResource, value)
}

// WithResolutionResult sets the resolution-result field.
func WithResolutionResult(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldResolutionResult, value))
}

// WithResolutionModel sets the resolution-model field.
func WithResolutionModel(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldResolutionModel, value))
}

// WithResolutionEndpoints sets the resolution-endpoints field.
func WithResolutionEndpoints(value ...string) zap.Field {
	return zap.Array(FieldResolutionEndpoints, NewStringArrayMarshaller(value))
}

// WithAuthToken sets the auth-token field.
func WithAuthToken(value string) zap.Field {
	return zap.String(FieldAuthToken, value)
}

// WithAuthTokens sets the auth-tokens field.
func WithAuthTokens(value ...string) zap.Field {
	return zap.Array(FieldAuthTokens, NewStringArrayMarshaller(value))
}

// WithAddress sets the address field.
func WithAddress(value string) zap.Field {
	return zap.String(FieldAddress, value)
}

// WithAttributedTo sets the attributed-to field.
func WithAttributedTo(value string) zap.Field {
	return zap.String(FieldAttributedTo, value)
}

// WithAnchorLink sets the anchor-link field.
func WithAnchorLink(value []byte) zap.Field {
	return zap.String(FieldAnchorLink, string(value))
}

// WithAnchorLinkset sets the anchor-linkset field.
func WithAnchorLinkset(value []byte) zap.Field {
	return zap.String(FieldAnchorLinkset, string(value))
}

// WithVersion sets the version field.
func WithVersion(value string) zap.Field {
	return zap.String(FieldVersion, value)
}

// WithDeliveryAttempts sets the delivery-attempts field.
func WithDeliveryAttempts(value int) zap.Field {
	return zap.Int(FieldDeliveryAttempts, value)
}

// WithProperty sets the property field.
func WithProperty(value string) zap.Field {
	return zap.String(FieldProperty, value)
}

// WithStoreName sets the store-name field.
func WithStoreName(value string) zap.Field {
	return zap.String(FieldStorageName, value)
}

// WithIssuer sets the issuer field.
func WithIssuer(value string) zap.Field {
	return zap.String(FieldIssuer, value)
}

// WithStatus sets the status field.
func WithStatus(value string) zap.Field {
	return zap.String(FieldStatus, value)
}

// WithLogURL sets the log-url field.
func WithLogURL(value fmt.Stringer) zap.Field {
	return zap.Stringer(FieldLogURL, value)
}

// WithLogURLString sets the log-url field.
func WithLogURLString(value string) zap.Field {
	return zap.String(FieldLogURL, value)
}

// WithNamespace sets the namespace field.
func WithNamespace(value string) zap.Field {
	return zap.String(FieldNamespace, value)
}

// WithCanonicalRef sets the canonical-ref field.
func WithCanonicalRef(value string) zap.Field {
	return zap.String(FieldCanonicalRef, value)
}

// WithAnchorString sets the anchor-string field.
func WithAnchorString(value string) zap.Field {
	return zap.String(FieldAnchorString, value)
}

// WithJRD sets the jrd field.
func WithJRD(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldJRD, value))
}

// WithBackoff sets the backoff field.
func WithBackoff(value time.Duration) zap.Field {
	return zap.Duration(FieldBackoff, value)
}

// WithTimeout sets the timeout field.
func WithTimeout(value time.Duration) zap.Field {
	return zap.Duration(FieldTimeout, value)
}

// WithLogMonitor sets the log-monitor field.
func WithLogMonitor(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldLogMonitor, value))
}

// WithLogMonitors sets the log-monitors field.
func WithLogMonitors(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldLogMonitors, value))
}

// WithMaxTime sets the max-time field.
func WithMaxTime(value time.Duration) zap.Field {
	return zap.Duration(FieldMaxTime, value)
}

// WithIndex sets the index field.
func WithIndex(value int) zap.Field {
	return zap.Int(FieldIndex, value)
}

// WithIndexUint64 sets the index field.
func WithIndexUint64(value uint64) zap.Field {
	return zap.Uint64(FieldIndex, value)
}

// WithFromIndexUint64 sets the from-index field.
func WithFromIndexUint64(value uint64) zap.Field {
	return zap.Uint64(FieldFromIndex, value)
}

// WithToIndexUint64 sets the to-index field.
func WithToIndexUint64(value uint64) zap.Field {
	return zap.Uint64(FieldToIndex, value)
}

// WithSource sets the source field.
func WithSource(value string) zap.Field {
	return zap.String(FieldSource, value)
}

// WithAge sets the age field.
func WithAge(value time.Duration) zap.Field {
	return zap.Duration(FieldAge, value)
}

// WithMinAge sets the min-age field.
func WithMinAge(value time.Duration) zap.Field {
	return zap.Duration(FieldMinAge, value)
}

// WithLogSpec sets the logSpec field.
func WithLogSpec(value string) zap.Field {
	return zap.String(FieldLogSpec, value)
}

// WithTracingProvider sets the tracingProvider field.
func WithTracingProvider(value string) zap.Field {
	return zap.String(FieldTracingProvider, value)
}

// WithMaxOperationsToRepost sets the maxOperationsToRepost field.
func WithMaxOperationsToRepost(value int) zap.Field {
	return zap.Int(FieldMaxOperationsToRepost, value)
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

// ObjectMarshaller uses reflection to marshal an object's fields.
type ObjectMarshaller struct {
	key string
	obj interface{}
}

// NewObjectMarshaller returns a new ObjectMarshaller.
func NewObjectMarshaller(key string, obj interface{}) *ObjectMarshaller {
	return &ObjectMarshaller{key: key, obj: obj}
}

// MarshalLogObject marshals the object's fields.
func (m *ObjectMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	return e.AddReflected(m.key, m.obj)
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
