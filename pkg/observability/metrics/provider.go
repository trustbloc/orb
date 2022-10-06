/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"time"

	"github.com/trustbloc/orb/internal/pkg/log"
)

// Logger used by different metrics provider.
var Logger = log.New("metrics-provider")

// Constants used by different metrics provider.
const (
	// Namespace Organization namespace.
	Namespace = "orb"

	// ActivityPub ActivityPub.
	ActivityPub                   = "activitypub"
	ApPostTimeMetric              = "outbox_post_seconds"
	ApResolveInboxesTimeMetric    = "outbox_resolve_inboxes_seconds"
	ApInboxHandlerTimeMetric      = "inbox_handler_seconds"
	ApOutboxActivityCounterMetric = "outbox_count"

	// Anchor Anchor.
	Anchor                                         = "anchor"
	AnchorWriteTimeMetric                          = "write_seconds"
	AnchorWitnessMetric                            = "witness_seconds"
	AnchorProcessWitnessedMetric                   = "process_witnessed_seconds"
	AnchorWriteBuildCredTimeMetric                 = "write_build_cred_seconds"
	AnchorWriteGetWitnessesTimeMetric              = "write_get_witnesses_seconds"
	AnchorWriteSignCredTimeMetric                  = "write_sign_cred_seconds" //nolint:gosec
	AnchorWritePostOfferActivityTimeMetric         = "write_post_offer_activity_seconds"
	AnchorWriteGetPreviousAnchorsGetBulkTimeMetric = "write_get_previous_anchor_get_bulk_seconds"
	AnchorWriteGetPreviousAnchorsTimeMetric        = "write_get_previous_anchor_seconds"
	AnchorWriteStoreTimeMetric                     = "write_store_seconds"
	AnchorWriteSignWithLocalWitnessTimeMetric      = "write_sign_with_local_witness_seconds"
	AnchorWriteSignWithServerKeyTimeMetric         = "write_sign_with_server_key_seconds"
	AnchorWriteSignLocalWitnessLogTimeMetric       = "write_sign_local_witness_log_seconds"
	AnchorWriteSignLocalWatchTimeMetric            = "write_sign_local_watch_seconds"
	AnchorWriteResolveHostMetaLinkTimeMetric       = "write_resolve_host_meta_link_seconds"

	// OperationQueue Operation queue.
	OperationQueue                 = "opqueue"
	OpQueueAddOperationTimeMetric  = "add_operation_seconds"
	OpQueueBatchCutTimeMetric      = "batch_cut_seconds"
	OpQueueBatchRollbackTimeMetric = "batch_rollback_seconds"
	OpQueueBatchSizeMetric         = "batch_size"

	// Observer Observer.
	Observer                        = "observer"
	ObserverProcessAnchorTimeMetric = "process_anchor_seconds"
	ObserverProcessDIDTimeMetric    = "process_did_seconds"

	// Cas CAS.
	Cas                    = "cas"
	CasWriteTimeMetric     = "write_seconds"
	CasResolveTimeMetric   = "resolve_seconds"
	CasCacheHitCountMetric = "cache_hit_count"
	CasReadTimeMetric      = "read_seconds"

	// Document handler.
	Document                  = "document"
	DocCreateUpdateTimeMetric = "create_update_seconds"
	DocResolveTimeMetric      = "resolve_seconds"

	// DB DB.
	DB                  = "db"
	DBPutTimeMetric     = "put_seconds"
	DBGetTimeMetric     = "get_seconds"
	DBGetTagsTimeMetric = "get_tags_seconds"
	DBGetBulkTimeMetric = "get_bulk_seconds"
	DBQueryTimeMetric   = "query_seconds"
	DBDeleteTimeMetric  = "delete_seconds"
	DBBatchTimeMetric   = "batch_seconds"

	// Vct VCT.
	Vct                                  = "vct"
	VctWitnessAddProofVCTNilTimeMetric   = "witness_add_proof_vct_nil_seconds"
	VctWitnessAddVCTimeMetric            = "witness_add_vc_seconds"
	VctWitnessAddProofTimeMetric         = "witness_add_proof_seconds"
	VctWitnessWebFingerTimeMetric        = "witness_webfinger_seconds"
	VctWitnessVerifyVCTTimeMetric        = "witness_verify_vct_signature_seconds"
	VctAddProofParseCredentialTimeMetric = "witness_add_proof_parse_credential_seconds" //nolint:gosec
	VctAddProofSignTimeMetric            = "witness_add_proof_sign_seconds"

	// Signer Signer.
	Signer                         = "signer"
	SignerGetKeyTimeMetric         = "get_key_seconds"
	SignerSignMetric               = "sign_seconds"
	SignerAddLinkedDataProofMetric = "add_linked_data_proof_seconds"

	// Resolver Resolver.
	Resolver = "resolver"

	ResolverResolveDocumentLocallyTimeMetric          = "resolve_document_locally_seconds"
	ResolverGetAnchorOriginEndpointTimeMetric         = "get_anchor_origin_endpoint_seconds"
	ResolverResolveDocumentFromAnchorOriginTimeMetric = "resolve_document_from_anchor_origin_seconds"
	ResolverResolveDocumentFromCreateStoreTimeMetric  = "resolve_document_from_create_document_store_seconds"
	ResolverDeleteDocumentFromCreateStoreTimeMetric   = "delete_document_from_create_document_store_seconds"
	ResolverVerifyCIDTimeMetric                       = "verify_cid_seconds"
	ResolverRequestDiscoveryTimeMetric                = "request_discovery_seconds"

	// WebResolver Resolver.
	WebResolver                = "web_resolver"
	WebResolverResolveDocument = "resolve_document"

	// Decorator decorator.
	Decorator = "decorator"

	DecoratorDecorateTimeMetric                      = "decorate_seconds"
	DecoratorProcessorResolveTimeMetric              = "processor_resolve_seconds"
	DecoratorGetAOEndpointAndResolveFromAOTimeMetric = "get_ao_endpoint_and_resolve_from_ao_seconds"

	// Operations Operations.
	Operations = "operations"

	UnpublishedPutOperationTimeMetric          = "put_unpublished_operation_seconds"
	UnpublishedGetOperationsTimeMetric         = "get_unpublished_operations_seconds"
	UnpublishedCalculateOperationKeyTimeMetric = "calculate_unpublished_operation_key_seconds"

	PublishedPutOperationsTimeMetric = "put_published_operations_seconds"
	PublishedGetOperationsTimeMetric = "get_published_operations_seconds"

	// CoreOperations Core operations processor.
	CoreOperations = "core"

	CoreProcessOperationTimeMetrics       = "process_operation_seconds"
	CoreGetProtocolVersionTimeMetrics     = "get_protocol_version_seconds"
	CoreParseOperationTimeMetrics         = "parse_operation_seconds"
	CoreValidateOperationTimeMetrics      = "validate_operation_seconds"
	CoreDecorateOperationTimeMetrics      = "decorate_operation_seconds"
	CoreAddUnpublishedOperationTimeMatrix = "add_unpublished_operation_seconds"
	CoreAddOperationToBatchTimeMatrix     = "add_operation_to_batch_seconds"
	CoreGetCreateOperationResult          = "get_create_operation_result_seconds"
	CoreHTTPCreateUpdateTimeMetrics       = "http_create_update_seconds"
	CoreHTTPResolveTimeMetrics            = "http_resolve_seconds"
	CoreCASWriteSizeMetrics               = "cas_write_size"

	// Aws AWS kms.
	Aws                           = "aws"
	AwsSignCountMetric            = "sign_count"
	AwsSignTimeMetric             = "sign_seconds"
	AwsExportPublicKeyCountMetric = "export_publickey_count"
	AwsExportPublicKeyTimeMetric  = "export_publickey_seconds"
	AwsVerifyCountMetric          = "Verify_count"
	AwsVerifyTimeMetric           = "Verify_seconds"
)

// Provider is an interface for metrics provider.
type Provider interface {
	// Create creates a metrics provider instance
	Create() error
	// Destroy destroys the metrics provider instance
	Destroy() error
	// Metrics providers metrics
	Metrics() Metrics
}

// Metrics is an interface for the metrics to be supported by the provider.
//
//nolint:interfacebloat
type Metrics interface {
	CASIncrementCacheHitCount()
	CASWriteTime(value time.Duration)
	CASReadTime(casType string, value time.Duration)
	PutPublishedOperations(duration time.Duration)
	GetPublishedOperations(duration time.Duration)
	CASResolveTime(value time.Duration)
	PutUnpublishedOperation(duration time.Duration)
	GetUnpublishedOperations(duration time.Duration)
	CalculateUnpublishedOperationKey(duration time.Duration)
	SignerSign(value time.Duration)
	SignerGetKey(value time.Duration)
	SignerAddLinkedDataProof(value time.Duration)
	WitnessAnchorCredentialTime(duration time.Duration)
	WitnessAddProofVctNil(value time.Duration)
	WitnessAddVC(value time.Duration)
	WitnessAddProof(value time.Duration)
	WitnessWebFinger(value time.Duration)
	WitnessVerifyVCTSignature(value time.Duration)
	AddProofParseCredential(value time.Duration)
	AddProofSign(value time.Duration)
	ProcessAnchorTime(value time.Duration)
	ProcessDIDTime(value time.Duration)
	InboxHandlerTime(activityType string, value time.Duration)
	OutboxPostTime(value time.Duration)
	OutboxResolveInboxesTime(value time.Duration)
	OutboxIncrementActivityCount(activityType string)
	WriteAnchorTime(value time.Duration)
	WriteAnchorBuildCredentialTime(value time.Duration)
	WriteAnchorGetWitnessesTime(value time.Duration)
	WriteAnchorStoreTime(value time.Duration)
	ProcessWitnessedAnchorCredentialTime(value time.Duration)
	WriteAnchorSignCredentialTime(value time.Duration)
	WriteAnchorPostOfferActivityTime(value time.Duration)
	WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration)
	WriteAnchorGetPreviousAnchorsTime(value time.Duration)
	WriteAnchorSignWithLocalWitnessTime(value time.Duration)
	WriteAnchorSignWithServerKeyTime(value time.Duration)
	WriteAnchorSignLocalWitnessLogTime(value time.Duration)
	WriteAnchorSignLocalWatchTime(value time.Duration)
	WriteAnchorResolveHostMetaLinkTime(value time.Duration)
	AddOperationTime(value time.Duration)
	BatchCutTime(value time.Duration)
	BatchRollbackTime(value time.Duration)
	BatchSize(value float64)
	DecorateTime(duration time.Duration)
	ProcessorResolveTime(duration time.Duration)
	GetAOEndpointAndResolveDocumentFromAOTime(duration time.Duration)
	ProcessOperation(duration time.Duration)
	GetProtocolVersionTime(since time.Duration)
	ParseOperationTime(since time.Duration)
	ValidateOperationTime(since time.Duration)
	DecorateOperationTime(since time.Duration)
	AddUnpublishedOperationTime(since time.Duration)
	AddOperationToBatchTime(since time.Duration)
	GetCreateOperationResultTime(since time.Duration)
	SignCount()
	SignTime(value time.Duration)
	ExportPublicKeyCount()
	ExportPublicKeyTime(value time.Duration)
	VerifyCount()
	VerifyTime(value time.Duration)
	DocumentResolveTime(duration time.Duration)
	ResolveDocumentLocallyTime(duration time.Duration)
	GetAnchorOriginEndpointTime(duration time.Duration)
	ResolveDocumentFromAnchorOriginTime(duration time.Duration)
	DeleteDocumentFromCreateDocumentStoreTime(duration time.Duration)
	ResolveDocumentFromCreateDocumentStoreTime(duration time.Duration)
	VerifyCIDTime(duration time.Duration)
	RequestDiscoveryTime(duration time.Duration)
	DocumentCreateUpdateTime(duration time.Duration)
	WebDocumentResolveTime(duration time.Duration)
	HTTPCreateUpdateTime(duration time.Duration)
	HTTPResolveTime(duration time.Duration)
	DBPutTime(dbType string, duration time.Duration)
	DBGetTime(dbType string, duration time.Duration)
	DBGetTagsTime(dbType string, duration time.Duration)
	DBGetBulkTime(dbType string, duration time.Duration)
	DBQueryTime(dbType string, duration time.Duration)
	DBDeleteTime(dbType string, duration time.Duration)
	DBBatchTime(dbType string, duration time.Duration)
	CASWriteSize(dataType string, size int)
}
