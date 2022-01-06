/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/trustbloc/edge-core/pkg/log"
)

const (
	namespace = "orb"

	// ActivityPub.
	activityPub                   = "activitypub"
	apPostTimeMetric              = "outbox_post_seconds"
	apResolveInboxesTimeMetric    = "outbox_resolve_inboxes_seconds"
	apInboxHandlerTimeMetric      = "inbox_handler_seconds"
	apOutboxActivityCounterMetric = "outbox_count"

	// Anchor.
	anchor                                         = "anchor"
	anchorWriteTimeMetric                          = "write_seconds"
	anchorWitnessMetric                            = "witness_seconds"
	anchorProcessWitnessedMetric                   = "process_witnessed_seconds"
	anchorWriteBuildCredTimeMetric                 = "write_build_cred_seconds"
	anchorWriteGetWitnessesTimeMetric              = "write_get_witnesses_seconds"
	anchorWriteSignCredTimeMetric                  = "write_sign_cred_seconds"
	anchorWritePostOfferActivityTimeMetric         = "write_post_offer_activity_seconds"
	anchorWriteGetPreviousAnchorsGetBulkTimeMetric = "write_get_previous_anchor_get_bulk_seconds"
	anchorWriteGetPreviousAnchorsTimeMetric        = "write_get_previous_anchor_seconds"
	anchorWriteSignWithLocalWitnessTimeMetric      = "write_sign_with_local_witness_seconds"
	anchorWriteSignWithServerKeyTimeMetric         = "write_sign_with_server_key_seconds"
	anchorWriteSignLocalWitnessLogTimeMetric       = "write_sign_local_witness_log_seconds"
	anchorWriteSignLocalStoreTimeMetric            = "write_sign_local_store_seconds"
	anchorWriteSignLocalWatchTimeMetric            = "write_sign_local_watch_seconds"
	anchorWriteResolveHostMetaLinkTimeMetric       = "write_resolve_host_meta_link_seconds"

	// Operation queue.
	operationQueue                 = "opqueue"
	opQueueAddOperationTimeMetric  = "add_operation_seconds"
	opQueueBatchCutTimeMetric      = "batch_cut_seconds"
	opQueueBatchRollbackTimeMetric = "batch_rollback_seconds"
	opQueueBatchSizeMetric         = "batch_size"

	// Observer.
	observer                        = "observer"
	observerProcessAnchorTimeMetric = "process_anchor_seconds"
	observerProcessDIDTimeMetric    = "process_did_seconds"

	// CAS.
	cas                    = "cas"
	casWriteTimeMetric     = "write_seconds"
	casResolveTimeMetric   = "resolve_seconds"
	casCacheHitCountMetric = "cache_hit_count"
	casReadTimeMetric      = "read_seconds"

	// Document handler.
	document                  = "document"
	docCreateUpdateTimeMetric = "create_update_seconds"
	docResolveTimeMetric      = "resolve_seconds"

	// DB.
	db                  = "db"
	dbPutTimeMetric     = "put_seconds"
	dbGetTimeMetric     = "get_seconds"
	dbGetTagsTimeMetric = "get_tags_seconds"
	dbGetBulkTimeMetric = "get_bulk_seconds"
	dbQueryTimeMetric   = "query_seconds"
	dbDeleteTimeMetric  = "delete_seconds"
	dbBatchTimeMetric   = "batch_seconds"

	// VCT.
	vct                                  = "vct"
	vctWitnessAddProofVCTNilTimeMetric   = "witness_add_proof_vct_nil_seconds"
	vctWitnessAddVCTimeMetric            = "witness_add_vc_seconds"
	vctWitnessAddProofTimeMetric         = "witness_add_proof_seconds"
	vctWitnessWebFingerTimeMetric        = "witness_webfinger_seconds"
	vctWitnessVerifyVCTTimeMetric        = "witness_verify_vct_signature_seconds"
	vctAddProofParseCredentialTimeMetric = "witness_add_proof_parse_credential_seconds"
	vctAddProofSignTimeMetric            = "witness_add_proof_sign_seconds"

	// Signer.
	signer                         = "signer"
	signerGetKeyTimeMetric         = "get_key_seconds"
	signerSignMetric               = "sign_seconds"
	signerAddLinkedDataProofMetric = "add_linked_data_proof_seconds"

	// Resolver.
	resolver = "resolver"

	resolverResolveDocumentLocallyTimeMetric          = "resolve_document_locally_seconds"
	resolverGetAnchorOriginEndpointTimeMetric         = "get_anchor_origin_endpoint_seconds"
	resolverResolveDocumentFromAnchorOriginTimeMetric = "resolve_document_from_anchor_origin_seconds"
	resolverResolveDocumentFromCreateStoreTimeMetric  = "resolve_document_from_create_document_store_seconds"
	resolverDeleteDocumentFromCreateStoreTimeMetric   = "delete_document_from_create_document_store_seconds"
	resolverVerifyCIDTimeMetric                       = "verify_cid_seconds"
	resolverRequestDiscoveryTimeMetric                = "request_discovery_seconds"

	// Decorator.
	decorator = "decorator"

	decoratorDecorateTimeMetric                      = "decorate_seconds"
	decoratorProcessorResolveTimeMetric              = "processor_resolve_seconds"
	decoratorGetAOEndpointAndResolveFromAOTimeMetric = "get_ao_endpoint_and_resolve_from_ao_seconds"

	// Operations.
	operations = "operations"

	unpublishedPutOperationTimeMetric          = "put_unpublished_operation_seconds"
	unpublishedGetOperationsTimeMetric         = "get_unpublished_operations_seconds"
	unpublishedCalculateOperationKeyTimeMetric = "calculate_unpublished_operation_key_seconds"

	publishedPutOperationsTimeMetric = "put_published_operations_seconds"
	publishedGetOperationsTimeMetric = "get_published_operations_seconds"

	// Core operations processor.
	coreOperations = "core"

	coreProcessOperationTimeMetrics       = "process_operation_seconds"
	coreGetProtocolVersionTimeMetrics     = "get_protocol_version_seconds"
	coreParseOperationTimeMetrics         = "parse_operation_seconds"
	coreValidateOperationTimeMetrics      = "validate_operation_seconds"
	coreDecorateOperationTimeMetrics      = "decorate_operation_seconds"
	coreAddUnpublishedOperationTimeMatrix = "add_unpublished_operation_seconds"
	coreAddOperationToBatchTimeMatrix     = "add_operation_to_batch_seconds"
	coreGetCreateOperationResult          = "get_create_operation_result_seconds"
	coreHTTPCreateUpdateTimeMetrics       = "http_create_update_seconds"
	coreHTTPResolveTimeMetrics            = "http_resolve_seconds"

	// AMQP.
	amqp                            = "amqp"
	amqpOpenPublisherChannelMetric  = "open_publisher_channel"
	amqpClosePublisherChannelMetric = "close_publisher_channel"
)

var logger = log.New("metrics")

var (
	createOnce sync.Once //nolint:gochecknoglobals
	instance   *Metrics  //nolint:gochecknoglobals
)

// Metrics manages the metrics for Orb.
type Metrics struct {
	apOutboxPostTime           prometheus.Histogram
	apOutboxResolveInboxesTime prometheus.Histogram
	apInboxHandlerTimes        map[string]prometheus.Histogram
	apOutboxActivityCounts     map[string]prometheus.Counter

	anchorWriteTime                          prometheus.Histogram
	anchorWitnessTime                        prometheus.Histogram
	anchorProcessWitnessedTime               prometheus.Histogram
	anchorWriteBuildCredTime                 prometheus.Histogram
	anchorWriteGetWitnessesTime              prometheus.Histogram
	anchorWriteSignCredTime                  prometheus.Histogram
	anchorWritePostOfferActivityTime         prometheus.Histogram
	anchorWriteGetPreviousAnchorsGetBulkTime prometheus.Histogram
	anchorWriteGetPreviousAnchorsTime        prometheus.Histogram
	anchorWriteSignWithLocalWitnessTime      prometheus.Histogram
	anchorWriteSignWithServerKeyTime         prometheus.Histogram
	anchorWriteSignLocalWitnessLogTime       prometheus.Histogram
	anchorWriteSignLocalStoreTime            prometheus.Histogram
	anchorWriteSignLocalWatchTime            prometheus.Histogram
	anchorWriteResolveHostMetaLinkTime       prometheus.Histogram

	opqueueAddOperationTime  prometheus.Histogram
	opqueueBatchCutTime      prometheus.Histogram
	opqueueBatchRollbackTime prometheus.Histogram
	opqueueBatchSize         prometheus.Gauge

	observerProcessAnchorTime prometheus.Histogram
	observerProcessDIDTime    prometheus.Histogram

	casWriteTime     prometheus.Histogram
	casResolveTime   prometheus.Histogram
	casCacheHitCount prometheus.Counter
	casReadTimes     map[string]prometheus.Histogram

	docCreateUpdateTime prometheus.Histogram
	docResolveTime      prometheus.Histogram

	dbPutTimes     map[string]prometheus.Histogram
	dbGetTimes     map[string]prometheus.Histogram
	dbGetTagsTimes map[string]prometheus.Histogram
	dbGetBulkTimes map[string]prometheus.Histogram
	dbQueryTimes   map[string]prometheus.Histogram
	dbDeleteTimes  map[string]prometheus.Histogram
	dbBatchTimes   map[string]prometheus.Histogram

	vctWitnessAddProofVCTNilTimes   prometheus.Histogram
	vctWitnessAddVCTimes            prometheus.Histogram
	vctWitnessAddProofTimes         prometheus.Histogram
	vctWitnessAddWebFingerTimes     prometheus.Histogram
	vctWitnessVerifyVCTimes         prometheus.Histogram
	vctAddProofParseCredentialTimes prometheus.Histogram
	vctAddProofSignTimes            prometheus.Histogram
	signerGetKeyTimes               prometheus.Histogram
	signerSignTimes                 prometheus.Histogram
	signerAddLinkedDataProofTimes   prometheus.Histogram

	resolverResolveDocumentLocallyTimes          prometheus.Histogram
	resolverGetAnchorOriginEndpointTimes         prometheus.Histogram
	resolverResolveDocumentFromAnchorOriginTimes prometheus.Histogram
	resolverDeleteDocumentFromCreateStoreTimes   prometheus.Histogram
	resolverResolveDocumentFromCreateStoreTimes  prometheus.Histogram
	resolverVerifyCIDTimes                       prometheus.Histogram
	resolverRequestDiscoveryTimes                prometheus.Histogram

	decoratorDecorateTime                      prometheus.Histogram
	decoratorProcessorResolveTime              prometheus.Histogram
	decoratorGetAOEndpointAndResolveFromAOTime prometheus.Histogram

	unpublishedPutOperationTime          prometheus.Histogram
	unpublishedGetOperationsTime         prometheus.Histogram
	unpublishedCalculateOperationKeyTime prometheus.Histogram
	publishedPutOperationsTime           prometheus.Histogram
	publishedGetOperationsTime           prometheus.Histogram

	coreProcessOperationTime         prometheus.Histogram
	coreGetProtocolVersionTime       prometheus.Histogram
	coreParseOperationTime           prometheus.Histogram
	coreValidateOperationTime        prometheus.Histogram
	coreDecorateOperationTime        prometheus.Histogram
	coreAddUnpublishedOperationTime  prometheus.Histogram
	coreAddOperationToBatchTime      prometheus.Histogram
	coreGetCreateOperationResultTime prometheus.Histogram
	coreHTTPCreateUpdateTime         prometheus.Histogram
	coreHTTPResolveTime              prometheus.Histogram

	amqpOpenPublisherChannelTime  prometheus.Histogram
	amqpClosePublisherChannelTime prometheus.Histogram
}

// Get returns an Orb metrics provider.
func Get() *Metrics {
	createOnce.Do(func() {
		instance = newMetrics()
	})

	return instance
}

func newMetrics() *Metrics { //nolint:funlen,gocyclo,cyclop
	activityTypes := []string{"Create", "Announce", "Offer", "Like", "Follow", "InviteWitness", "Accept", "Reject"}
	dbTypes := []string{"CouchDB", "MongoDB"}

	m := &Metrics{
		apOutboxPostTime:                             newOutboxPostTime(),
		apOutboxResolveInboxesTime:                   newOutboxResolveInboxesTime(),
		anchorWriteTime:                              newAnchorWriteTime(),
		anchorWriteBuildCredTime:                     newAnchorWriteBuildCredTime(),
		anchorWriteGetWitnessesTime:                  newAnchorWriteGetWitnessesTime(),
		anchorWriteSignCredTime:                      newAnchorWriteSignCredTime(),
		anchorWritePostOfferActivityTime:             newAnchorWritePostOfferActivityTime(),
		anchorWriteGetPreviousAnchorsGetBulkTime:     newAnchorWriteGetPreviousAnchorsGetBulkTime(),
		anchorWriteGetPreviousAnchorsTime:            newAnchorWriteGetPreviousAnchorsTime(),
		anchorWitnessTime:                            newAnchorWitnessTime(),
		anchorProcessWitnessedTime:                   newAnchorProcessWitnessedTime(),
		anchorWriteSignWithLocalWitnessTime:          newAnchorWriteSignWithLocalWitnessTime(),
		anchorWriteSignWithServerKeyTime:             newAnchorWriteSignWithServerKeyTime(),
		anchorWriteSignLocalWitnessLogTime:           newAnchorWriteSignLocalWitnessLogTime(),
		anchorWriteSignLocalStoreTime:                newAnchorWriteSignLocalStoreTime(),
		anchorWriteSignLocalWatchTime:                newAnchorWriteSignLocalWatchTime(),
		anchorWriteResolveHostMetaLinkTime:           newAnchorWriteResolveHostMetaLinkTime(),
		opqueueAddOperationTime:                      newOpQueueAddOperationTime(),
		opqueueBatchCutTime:                          newOpQueueBatchCutTime(),
		opqueueBatchRollbackTime:                     newOpQueueBatchRollbackTime(),
		opqueueBatchSize:                             newOpQueueBatchSize(),
		observerProcessAnchorTime:                    newObserverProcessAnchorTime(),
		observerProcessDIDTime:                       newObserverProcessDIDTime(),
		casWriteTime:                                 newCASWriteTime(),
		casResolveTime:                               newCASResolveTime(),
		casReadTimes:                                 newCASReadTimes(),
		casCacheHitCount:                             newCASCacheHitCount(),
		docCreateUpdateTime:                          newDocCreateUpdateTime(),
		docResolveTime:                               newDocResolveTime(),
		apInboxHandlerTimes:                          newInboxHandlerTimes(activityTypes),
		apOutboxActivityCounts:                       newOutboxActivityCounts(activityTypes),
		dbPutTimes:                                   newDBPutTime(dbTypes),
		dbGetTimes:                                   newDBGetTime(dbTypes),
		dbGetTagsTimes:                               newDBGetTagsTime(dbTypes),
		dbGetBulkTimes:                               newDBGetBulkTime(dbTypes),
		dbQueryTimes:                                 newDBQueryTime(dbTypes),
		dbDeleteTimes:                                newDBDeleteTime(dbTypes),
		dbBatchTimes:                                 newDBBatchTime(dbTypes),
		vctWitnessAddProofVCTNilTimes:                newVCTWitnessAddProofVCTNilTime(),
		vctWitnessAddVCTimes:                         newVCTWitnessAddVCTime(),
		vctWitnessAddProofTimes:                      newVCTWitnessAddProofTime(),
		vctWitnessAddWebFingerTimes:                  newVCTWitnessWebFingerTime(),
		vctWitnessVerifyVCTimes:                      newVCTWitnessVerifyVCTTime(),
		vctAddProofParseCredentialTimes:              newVCTAddProofParseCredentialTime(),
		vctAddProofSignTimes:                         newVCTAddProofSignTime(),
		signerGetKeyTimes:                            newSignerGetKeyTime(),
		signerSignTimes:                              newSignerSignTime(),
		signerAddLinkedDataProofTimes:                newSignerAddLinkedDataProofTime(),
		resolverResolveDocumentLocallyTimes:          newResolverResolveDocumentLocallyTime(),
		resolverGetAnchorOriginEndpointTimes:         newResolverGetAnchorOriginEndpointTime(),
		resolverResolveDocumentFromAnchorOriginTimes: newResolverResolveDocumentFromAnchorOriginTime(),
		resolverDeleteDocumentFromCreateStoreTimes:   newResolverDeleteDocumentFromCreateStoreTime(),
		resolverResolveDocumentFromCreateStoreTimes:  newResolverResolveDocumentFromCreateStoreTime(),
		resolverVerifyCIDTimes:                       newResolverVerifyCIDTime(),
		resolverRequestDiscoveryTimes:                newResolverRequestDiscoveryTime(),
		decoratorDecorateTime:                        newDecoratorDecorateTime(),
		decoratorProcessorResolveTime:                newDecoratorProcessorResolveTime(),
		decoratorGetAOEndpointAndResolveFromAOTime:   newDecoratorGetAOEndpointAndResolveFromAOTime(),
		unpublishedPutOperationTime:                  newUnpublishedPutOperationTime(),
		unpublishedGetOperationsTime:                 newUnpublishedGetOperationsTime(),
		unpublishedCalculateOperationKeyTime:         newUnpublishedCalculateKeyTime(),
		publishedPutOperationsTime:                   newPublishedPutOperationsTime(),
		publishedGetOperationsTime:                   newPublishedGetOperationsTime(),
		coreProcessOperationTime:                     newCoreProcessOperationTime(),
		coreGetProtocolVersionTime:                   newCoreGetProtocolVersionTime(),
		coreParseOperationTime:                       newCoreParseOperationTime(),
		coreValidateOperationTime:                    newCoreValidateOperationTime(),
		coreDecorateOperationTime:                    newCoreDecorateOperationTime(),
		coreAddUnpublishedOperationTime:              newCoreAddUnpublishedOperationTime(),
		coreAddOperationToBatchTime:                  newCoreAddOperationToBatchTime(),
		coreGetCreateOperationResultTime:             newCoreGetCreateOperationResultTime(),
		coreHTTPCreateUpdateTime:                     newCoreHTTPCreateUpdateTime(),
		coreHTTPResolveTime:                          newCoreHTTPResolveTime(),
		amqpOpenPublisherChannelTime:                 newAMQPOpenPublisherChannelTime(),
		amqpClosePublisherChannelTime:                newAMQPClosePublisherChannelTime(),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime, m.apOutboxResolveInboxesTime,
		m.anchorWriteTime, m.anchorWitnessTime, m.anchorProcessWitnessedTime, m.anchorWriteBuildCredTime,
		m.anchorWriteGetWitnessesTime, m.anchorWriteSignCredTime, m.anchorWritePostOfferActivityTime,
		m.anchorWriteGetPreviousAnchorsGetBulkTime, m.anchorWriteGetPreviousAnchorsTime,
		m.anchorWriteSignWithLocalWitnessTime, m.anchorWriteSignWithServerKeyTime, m.anchorWriteSignLocalWitnessLogTime,
		m.anchorWriteSignLocalStoreTime, m.anchorWriteSignLocalWatchTime,
		m.opqueueAddOperationTime, m.opqueueBatchCutTime, m.opqueueBatchRollbackTime,
		m.opqueueBatchSize, m.observerProcessAnchorTime, m.observerProcessDIDTime,
		m.casWriteTime, m.casResolveTime, m.casCacheHitCount,
		m.docCreateUpdateTime, m.docResolveTime,
		m.vctWitnessAddProofVCTNilTimes, m.vctWitnessAddVCTimes, m.vctWitnessAddProofTimes,
		m.vctWitnessAddWebFingerTimes, m.vctWitnessVerifyVCTimes, m.vctAddProofParseCredentialTimes,
		m.vctAddProofSignTimes, m.signerSignTimes, m.signerGetKeyTimes, m.signerAddLinkedDataProofTimes,
		m.anchorWriteResolveHostMetaLinkTime,
		m.resolverResolveDocumentLocallyTimes, m.resolverGetAnchorOriginEndpointTimes,
		m.resolverResolveDocumentFromAnchorOriginTimes,
		m.resolverResolveDocumentFromCreateStoreTimes, m.resolverDeleteDocumentFromCreateStoreTimes,
		m.resolverVerifyCIDTimes, m.resolverRequestDiscoveryTimes,
		m.decoratorDecorateTime, m.decoratorProcessorResolveTime, m.decoratorGetAOEndpointAndResolveFromAOTime,
		m.unpublishedPutOperationTime, m.unpublishedGetOperationsTime, m.unpublishedCalculateOperationKeyTime,
		m.publishedPutOperationsTime, m.publishedGetOperationsTime,
		m.coreProcessOperationTime, m.coreGetProtocolVersionTime,
		m.coreParseOperationTime, m.coreValidateOperationTime, m.coreDecorateOperationTime,
		m.coreAddUnpublishedOperationTime, m.coreAddOperationToBatchTime, m.coreGetCreateOperationResultTime,
		m.coreHTTPCreateUpdateTime, m.coreHTTPResolveTime, m.amqpOpenPublisherChannelTime, m.amqpClosePublisherChannelTime,
	)

	for _, c := range m.apInboxHandlerTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbPutTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetTagsTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbGetBulkTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbBatchTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbDeleteTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.dbQueryTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range m.apOutboxActivityCounts {
		prometheus.MustRegister(c)
	}

	for _, c := range m.casReadTimes {
		prometheus.MustRegister(c)
	}

	return m
}

// OutboxPostTime records the time it takes to post a message to the outbox.
func (m *Metrics) OutboxPostTime(value time.Duration) {
	m.apOutboxPostTime.Observe(value.Seconds())

	logger.Debugf("OutboxPost time: %s", value)
}

// OutboxResolveInboxesTime records the time it takes to resolve inboxes for an outbox post.
func (m *Metrics) OutboxResolveInboxesTime(value time.Duration) {
	m.apOutboxResolveInboxesTime.Observe(value.Seconds())

	logger.Debugf("OutboxResolveInboxes time: %s", value)
}

// InboxHandlerTime records the time it takes to handle an activity posted to the inbox.
func (m *Metrics) InboxHandlerTime(activityType string, value time.Duration) {
	if c, ok := m.apInboxHandlerTimes[activityType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("InboxHandler time for activity [%s]: %s", activityType, value)
}

// OutboxIncrementActivityCount increments the number of activities of the given type posted to the outbox.
func (m *Metrics) OutboxIncrementActivityCount(activityType string) {
	if c, ok := m.apOutboxActivityCounts[activityType]; ok {
		c.Inc()
	}
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (m *Metrics) WriteAnchorTime(value time.Duration) {
	m.anchorWriteTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor time: %s", value)
}

// WriteAnchorBuildCredentialTime records the time it takes to build credential inside write anchor.
func (m *Metrics) WriteAnchorBuildCredentialTime(value time.Duration) {
	m.anchorWriteBuildCredTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor build credential time: %s", value)
}

// WriteAnchorGetWitnessesTime records the time it takes to get witnesses inside write anchor.
func (m *Metrics) WriteAnchorGetWitnessesTime(value time.Duration) {
	m.anchorWriteGetWitnessesTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor get witness time: %s", value)
}

// WriteAnchorSignCredentialTime records the time it takes to sign credential inside write anchor.
func (m *Metrics) WriteAnchorSignCredentialTime(value time.Duration) {
	m.anchorWriteSignCredTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor sign credential time: %s", value)
}

// WriteAnchorPostOfferActivityTime records the time it takes to post offer activity inside write anchor.
func (m *Metrics) WriteAnchorPostOfferActivityTime(value time.Duration) {
	m.anchorWritePostOfferActivityTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor sign credential time: %s", value)
}

// WriteAnchorGetPreviousAnchorsGetBulkTime records the time it takes to get bulk inside previous anchor.
func (m *Metrics) WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration) {
	m.anchorWriteGetPreviousAnchorsGetBulkTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor getPreviousAnchor geBulk time: %s", value)
}

// WriteAnchorGetPreviousAnchorsTime records the time it takes to get previous anchor.
func (m *Metrics) WriteAnchorGetPreviousAnchorsTime(value time.Duration) {
	m.anchorWriteGetPreviousAnchorsTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor getPreviousAnchor time: %s", value)
}

// WriteAnchorSignWithLocalWitnessTime records the time it takes to sign with local witness.
func (m *Metrics) WriteAnchorSignWithLocalWitnessTime(value time.Duration) {
	m.anchorWriteSignWithLocalWitnessTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor sign with local witness time: %s", value)
}

// WriteAnchorSignWithServerKeyTime records the time it takes to sign with server key.
func (m *Metrics) WriteAnchorSignWithServerKeyTime(value time.Duration) {
	m.anchorWriteSignWithServerKeyTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor sign with server key time: %s", value)
}

// WriteAnchorSignLocalWitnessLogTime records the time it takes to witness log inside sign local.
func (m *Metrics) WriteAnchorSignLocalWitnessLogTime(value time.Duration) {
	m.anchorWriteSignLocalWitnessLogTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor witness log inside sign local time: %s", value)
}

// WriteAnchorSignLocalStoreTime records the time it takes to store inside sign local.
func (m *Metrics) WriteAnchorSignLocalStoreTime(value time.Duration) {
	m.anchorWriteSignLocalStoreTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor store inside sign local time: %s", value)
}

// WriteAnchorSignLocalWatchTime records the time it takes to watch inside sign local.
func (m *Metrics) WriteAnchorSignLocalWatchTime(value time.Duration) {
	m.anchorWriteSignLocalWatchTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor watch inside sign local time: %s", value)
}

// WriteAnchorResolveHostMetaLinkTime records the time it takes to resolve host meta link.
func (m *Metrics) WriteAnchorResolveHostMetaLinkTime(value time.Duration) {
	m.anchorWriteResolveHostMetaLinkTime.Observe(value.Seconds())

	logger.Debugf("WriteAnchor resolve host meta link time: %s", value)
}

// WitnessAnchorCredentialTime records the time it takes for a verifiable credential to gather proofs from all
// required witnesses (according to witness policy). The start time is when the verifiable credential is issued
// and the end time is the time that the witness policy is satisfied.
func (m *Metrics) WitnessAnchorCredentialTime(value time.Duration) {
	m.anchorWitnessTime.Observe(value.Seconds())

	logger.Debugf("WitnessAnchorCredential time: %s", value)
}

// ProcessWitnessedAnchorCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (m *Metrics) ProcessWitnessedAnchorCredentialTime(value time.Duration) {
	m.anchorProcessWitnessedTime.Observe(value.Seconds())

	logger.Debugf("ProcessWitnessedAnchorCredential time: %s", value)
}

// AddOperationTime records the time it takes to add an operation to the queue.
func (m *Metrics) AddOperationTime(value time.Duration) {
	m.opqueueAddOperationTime.Observe(value.Seconds())

	logger.Debugf("AddOperation time: %s", value)
}

// BatchCutTime records the time it takes to cut an operation batch. The duration is from the time
// that the first operation was added to the time that the batch is cut.
func (m *Metrics) BatchCutTime(value time.Duration) {
	m.opqueueBatchCutTime.Observe(value.Seconds())

	logger.Infof("BatchCut time: %s", value)
}

// BatchRollbackTime records the time it takes to roll back an operation batch (in case of a
// transient error). The duration is from the time that the first operation was added to the time
// that the batch is cut.
func (m *Metrics) BatchRollbackTime(value time.Duration) {
	m.opqueueBatchRollbackTime.Observe(value.Seconds())

	logger.Debugf("BatchRollback time: %s", value)
}

// BatchSize records the size of an operation batch.
func (m *Metrics) BatchSize(value float64) {
	m.opqueueBatchSize.Set(value)

	logger.Infof("BatchSize: %s", value)
}

// ProcessAnchorTime records the time it takes for the Observer to process an anchor credential.
func (m *Metrics) ProcessAnchorTime(value time.Duration) {
	m.observerProcessAnchorTime.Observe(value.Seconds())

	logger.Infof("ProcessAnchor time: %s", value)
}

// ProcessDIDTime records the time it takes for the Observer to process a DID.
func (m *Metrics) ProcessDIDTime(value time.Duration) {
	m.observerProcessDIDTime.Observe(value.Seconds())

	logger.Infof("ProcessDID time: %s", value)
}

// CASWriteTime records the time it takes to write a document to CAS.
func (m *Metrics) CASWriteTime(value time.Duration) {
	m.casWriteTime.Observe(value.Seconds())

	logger.Debugf("CASWrite time: %s", value)
}

// CASResolveTime records the time it takes to resolve a document from CAS.
func (m *Metrics) CASResolveTime(value time.Duration) {
	m.casResolveTime.Observe(value.Seconds())

	logger.Debugf("CASResolve time: %s", value)
}

// CASIncrementCacheHitCount increments the number of CAS cache hits.
func (m *Metrics) CASIncrementCacheHitCount() {
	m.casCacheHitCount.Inc()
}

// CASReadTime records the time it takes to read a document from CAS storage.
func (m *Metrics) CASReadTime(casType string, value time.Duration) {
	if c, ok := m.casReadTimes[casType]; ok {
		c.Observe(value.Seconds())
	}
}

// DocumentCreateUpdateTime records the time it takes the REST handler to process a create/update operation.
func (m *Metrics) DocumentCreateUpdateTime(value time.Duration) {
	m.docCreateUpdateTime.Observe(value.Seconds())

	logger.Debugf("DocumentCreateUpdate time: %s", value)
}

// DocumentResolveTime records the time it takes the REST handler to resolve a document.
func (m *Metrics) DocumentResolveTime(value time.Duration) {
	m.docResolveTime.Observe(value.Seconds())

	logger.Debugf("DocumentResolve time: %s", value)
}

// DBPutTime records the time it takes to store data in db.
func (m *Metrics) DBPutTime(dbType string, value time.Duration) {
	if c, ok := m.dbPutTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTime records the time it takes to get data in db.
func (m *Metrics) DBGetTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTagsTime records the time it takes to get tags in db.
func (m *Metrics) DBGetTagsTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTagsTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetBulkTime records the time it takes to get bulk in db.
func (m *Metrics) DBGetBulkTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetBulkTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBQueryTime records the time it takes to query in db.
func (m *Metrics) DBQueryTime(dbType string, value time.Duration) {
	if c, ok := m.dbQueryTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBDeleteTime records the time it takes to delete in db.
func (m *Metrics) DBDeleteTime(dbType string, value time.Duration) {
	if c, ok := m.dbDeleteTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBBatchTime records the time it takes to batch in db.
func (m *Metrics) DBBatchTime(dbType string, value time.Duration) {
	if c, ok := m.dbBatchTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// WitnessAddProofVctNil records vct witness.
func (m *Metrics) WitnessAddProofVctNil(value time.Duration) {
	m.vctWitnessAddProofVCTNilTimes.Observe(value.Seconds())

	logger.Debugf("vct witness add proof when vct nil time: %s", value)
}

// WitnessAddVC records vct witness add vc.
func (m *Metrics) WitnessAddVC(value time.Duration) {
	m.vctWitnessAddVCTimes.Observe(value.Seconds())

	logger.Debugf("vct witness add vc time: %s", value)
}

// WitnessAddProof records vct witness add proof.
func (m *Metrics) WitnessAddProof(value time.Duration) {
	m.vctWitnessAddProofTimes.Observe(value.Seconds())

	logger.Debugf("vct witness add vc proof: %s", value)
}

// WitnessWebFinger records vct witness web finger.
func (m *Metrics) WitnessWebFinger(value time.Duration) {
	m.vctWitnessAddWebFingerTimes.Observe(value.Seconds())

	logger.Debugf("vct witness web finger: %s", value)
}

// WitnessVerifyVCTSignature records vct witness verify vct.
func (m *Metrics) WitnessVerifyVCTSignature(value time.Duration) {
	m.vctWitnessVerifyVCTimes.Observe(value.Seconds())

	logger.Debugf("vct witness verify vct signature: %s", value)
}

// AddProofParseCredential records vct parse credential in add proof.
func (m *Metrics) AddProofParseCredential(value time.Duration) {
	m.vctAddProofParseCredentialTimes.Observe(value.Seconds())

	logger.Debugf("vct parse credential add proof: %s", value)
}

// AddProofSign records vct sign in add proof.
func (m *Metrics) AddProofSign(value time.Duration) {
	m.vctAddProofSignTimes.Observe(value.Seconds())

	logger.Debugf("vct sign add proof: %s", value)
}

// SignerGetKey records get key time.
func (m *Metrics) SignerGetKey(value time.Duration) {
	m.signerGetKeyTimes.Observe(value.Seconds())

	logger.Debugf("signer get key time: %s", value)
}

// SignerAddLinkedDataProof records add data linked proof.
func (m *Metrics) SignerAddLinkedDataProof(value time.Duration) {
	m.signerAddLinkedDataProofTimes.Observe(value.Seconds())

	logger.Debugf("signer add linked data proof time: %s", value)
}

// ResolveDocumentLocallyTime records resolving document locally.
func (m *Metrics) ResolveDocumentLocallyTime(value time.Duration) {
	m.resolverResolveDocumentLocallyTimes.Observe(value.Seconds())

	logger.Debugf("resolver resolve document locally time: %s", value)
}

// GetAnchorOriginEndpointTime records getting anchor origin endpoint information.
func (m *Metrics) GetAnchorOriginEndpointTime(value time.Duration) {
	m.resolverGetAnchorOriginEndpointTimes.Observe(value.Seconds())

	logger.Debugf("resolver get anchor origin endpoint time: %s", value)
}

// ResolveDocumentFromAnchorOriginTime records resolving document from anchor origin.
func (m *Metrics) ResolveDocumentFromAnchorOriginTime(value time.Duration) {
	m.resolverResolveDocumentFromAnchorOriginTimes.Observe(value.Seconds())

	logger.Debugf("resolver resolve document from anchor origin time: %s", value)
}

// DeleteDocumentFromCreateDocumentStoreTime records deleting document from create document store.
func (m *Metrics) DeleteDocumentFromCreateDocumentStoreTime(value time.Duration) {
	m.resolverDeleteDocumentFromCreateStoreTimes.Observe(value.Seconds())

	logger.Debugf("resolver delete document from create store time: %s", value)
}

// ResolveDocumentFromCreateDocumentStoreTime records resolving document from create document store.
func (m *Metrics) ResolveDocumentFromCreateDocumentStoreTime(value time.Duration) {
	m.resolverResolveDocumentFromCreateStoreTimes.Observe(value.Seconds())

	logger.Debugf("resolver resolve document from create store time: %s", value)
}

// VerifyCIDTime records verifying CID for document resolution.
func (m *Metrics) VerifyCIDTime(value time.Duration) {
	m.resolverVerifyCIDTimes.Observe(value.Seconds())

	logger.Debugf("resolver verify CID time: %s", value)
}

// RequestDiscoveryTime records the time it takes to request discovery.
func (m *Metrics) RequestDiscoveryTime(value time.Duration) {
	m.resolverRequestDiscoveryTimes.Observe(value.Seconds())

	logger.Debugf("resolver request discovery time: %s", value)
}

// DecorateTime records the time it takes to decorate operation (for update handler).
func (m *Metrics) DecorateTime(value time.Duration) {
	m.decoratorDecorateTime.Observe(value.Seconds())

	logger.Debugf("decorator decorate time: %s", value)
}

// ProcessorResolveTime records the time it takes for processor to resolve document
// when decorating operation (for update handler).
func (m *Metrics) ProcessorResolveTime(value time.Duration) {
	m.decoratorProcessorResolveTime.Observe(value.Seconds())

	logger.Debugf("decorator processor resolve time: %s", value)
}

// GetAOEndpointAndResolveDocumentFromAOTime records the time it takes to get anchor origin endpoint
// and resolve document from anchor origin when decorating operation (for update handler).
func (m *Metrics) GetAOEndpointAndResolveDocumentFromAOTime(value time.Duration) {
	m.decoratorGetAOEndpointAndResolveFromAOTime.Observe(value.Seconds())

	logger.Debugf("decorator get anchor origin endpoint and resolve from anchor origin time: %s", value)
}

// PutUnpublishedOperation records the time it takes to store unpublished operation.
func (m *Metrics) PutUnpublishedOperation(value time.Duration) {
	m.unpublishedPutOperationTime.Observe(value.Seconds())

	logger.Debugf("unpublished put operation time: %s", value)
}

// GetUnpublishedOperations records the time it takes to get unpublished operations for suffix.
func (m *Metrics) GetUnpublishedOperations(value time.Duration) {
	m.unpublishedGetOperationsTime.Observe(value.Seconds())

	logger.Debugf("unpublished get operations for suffix time: %s", value)
}

// CalculateUnpublishedOperationKey records the time to create unpublished operation key.
func (m *Metrics) CalculateUnpublishedOperationKey(value time.Duration) {
	m.unpublishedCalculateOperationKeyTime.Observe(value.Seconds())

	logger.Debugf("unpublished calculate operation key time: %s", value)
}

// PutPublishedOperations records the time to store published operations.
func (m *Metrics) PutPublishedOperations(value time.Duration) {
	m.publishedPutOperationsTime.Observe(value.Seconds())

	logger.Debugf("published put operations time: %s", value)
}

// GetPublishedOperations records the time to get published operations for suffix.
func (m *Metrics) GetPublishedOperations(value time.Duration) {
	m.publishedGetOperationsTime.Observe(value.Seconds())

	logger.Debugf("published get operations for suffix time: %s", value)
}

// ProcessOperation records the overall time to process operation.
func (m *Metrics) ProcessOperation(value time.Duration) {
	m.coreProcessOperationTime.Observe(value.Seconds())

	logger.Debugf("core process operation time: %s", value)
}

// GetProtocolVersionTime records the time to get protocol version.
func (m *Metrics) GetProtocolVersionTime(value time.Duration) {
	m.coreGetProtocolVersionTime.Observe(value.Seconds())

	logger.Debugf("core get protocol version(process operation): %s", value)
}

// ParseOperationTime records the time to parse operation.
func (m *Metrics) ParseOperationTime(value time.Duration) {
	m.coreParseOperationTime.Observe(value.Seconds())

	logger.Debugf("core parse operation(process operation): %s", value)
}

// ValidateOperationTime records the time to validate operation.
func (m *Metrics) ValidateOperationTime(value time.Duration) {
	m.coreValidateOperationTime.Observe(value.Seconds())

	logger.Debugf("core validate operation(process operation): %s", value)
}

// DecorateOperationTime records the time to decorate operation.
func (m *Metrics) DecorateOperationTime(value time.Duration) {
	m.coreDecorateOperationTime.Observe(value.Seconds())

	logger.Debugf("core decorate operation(process operation): %s", value)
}

// AddUnpublishedOperationTime records the time to add unpublished operation.
func (m *Metrics) AddUnpublishedOperationTime(value time.Duration) {
	m.coreAddUnpublishedOperationTime.Observe(value.Seconds())

	logger.Debugf("core add unpublished operation(process operation): %s", value)
}

// AddOperationToBatchTime records the time to add operation to batch.
func (m *Metrics) AddOperationToBatchTime(value time.Duration) {
	m.coreAddOperationToBatchTime.Observe(value.Seconds())

	logger.Debugf("core add operation to batch(process operation): %s", value)
}

// GetCreateOperationResultTime records the time to create operation result response.
func (m *Metrics) GetCreateOperationResultTime(value time.Duration) {
	m.coreGetCreateOperationResultTime.Observe(value.Seconds())

	logger.Debugf("core get create operation result(process operation): %s", value)
}

// HTTPCreateUpdateTime records the time rest call for create or update.
func (m *Metrics) HTTPCreateUpdateTime(value time.Duration) {
	m.coreHTTPCreateUpdateTime.Observe(value.Seconds())

	logger.Debugf("core http create update: %s", value)
}

// HTTPResolveTime records the time rest call for resolve.
func (m *Metrics) HTTPResolveTime(value time.Duration) {
	m.coreHTTPResolveTime.Observe(value.Seconds())

	logger.Debugf("core http resolve: %s", value)
}

// SignerSign records sign.
func (m *Metrics) SignerSign(value time.Duration) {
	m.signerSignTimes.Observe(value.Seconds())

	logger.Debugf("signer sign time: %s", value)
}

// OpenAMQPPublisherChannel records the time it takes to open an AMQP publisher channel.
func (m *Metrics) OpenAMQPPublisherChannel(value time.Duration) {
	m.amqpOpenPublisherChannelTime.Observe(value.Seconds())

	logger.Debugf("AMQP open channel time: %s", value)
}

// CloseAMQPPublisherChannel records the time it takes to close an AMQP publisher channel.
func (m *Metrics) CloseAMQPPublisherChannel(value time.Duration) {
	m.amqpClosePublisherChannelTime.Observe(value.Seconds())

	logger.Debugf("AMQP close channel time: %s", value)
}

func newCounter(subsystem, name, help string, labels prometheus.Labels) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newGauge(subsystem, name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	})
}

func newHistogram(subsystem, name, help string, labels prometheus.Labels) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newOutboxPostTime() prometheus.Histogram {
	return newHistogram(
		activityPub, apPostTimeMetric,
		"The time (in seconds) that it takes to post a message to the outbox.",
		nil,
	)
}

func newOutboxResolveInboxesTime() prometheus.Histogram {
	return newHistogram(
		activityPub, apResolveInboxesTimeMetric,
		"The time (in seconds) that it takes to resolve the inboxes of the destinations when posting to the outbox.",
		nil,
	)
}

func newInboxHandlerTimes(activityTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, activityType := range activityTypes {
		counters[activityType] = newHistogram(
			activityPub, apInboxHandlerTimeMetric,
			"The time (in seconds) that it takes to handle an activity posted to the inbox.",
			prometheus.Labels{"type": activityType},
		)
	}

	return counters
}

func newOutboxActivityCounts(activityTypes []string) map[string]prometheus.Counter {
	counters := make(map[string]prometheus.Counter)

	for _, activityType := range activityTypes {
		counters[activityType] = newCounter(
			activityPub, apOutboxActivityCounterMetric,
			"The number of activities posted to the outbox.",
			prometheus.Labels{"type": activityType},
		)
	}

	return counters
}

func newAnchorWriteTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteTimeMetric,
		"The time (in seconds) that it takes to write an anchor credential and post an 'Offer' activity.",
		nil,
	)
}

func newAnchorWitnessTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWitnessMetric,
		"The time (in seconds) that it takes for a verifiable credential to gather proofs from all required "+
			"witnesses (according to witness policy). The start time is when the verifiable credential is issued "+
			"and the end time is the time that the witness policy is satisfied.",
		nil,
	)
}

func newAnchorProcessWitnessedTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorProcessWitnessedMetric,
		"The time (in seconds) that it takes to process a witnessed anchor credential by publishing it to "+
			"the Observer and posting a 'Create' activity.",
		nil,
	)
}

func newAnchorWriteBuildCredTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteBuildCredTimeMetric,
		"The time (in seconds) that it takes to build credential inside write anchor.",
		nil,
	)
}

func newAnchorWriteGetWitnessesTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteGetWitnessesTimeMetric,
		"The time (in seconds) that it takes to get witnesses inside write anchor.",
		nil,
	)
}

func newAnchorWriteSignCredTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignCredTimeMetric,
		"The time (in seconds) that it takes to sign credential inside write anchor.",
		nil,
	)
}

func newAnchorWritePostOfferActivityTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWritePostOfferActivityTimeMetric,
		"The time (in seconds) that it takes to post offer activity inside write anchor.",
		nil,
	)
}

func newAnchorWriteGetPreviousAnchorsGetBulkTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteGetPreviousAnchorsGetBulkTimeMetric,
		"The time (in seconds) that it takes to get bulk inside get previous anchor.",
		nil,
	)
}

func newAnchorWriteGetPreviousAnchorsTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteGetPreviousAnchorsTimeMetric,
		"The time (in seconds) that it takes to get previous anchor.",
		nil,
	)
}

func newAnchorWriteSignWithLocalWitnessTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignWithLocalWitnessTimeMetric,
		"The time (in seconds) that it takes to sign with local witness.",
		nil,
	)
}

func newAnchorWriteSignWithServerKeyTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignWithServerKeyTimeMetric,
		"The time (in seconds) that it takes to sign with server key.",
		nil,
	)
}

func newAnchorWriteSignLocalWitnessLogTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignLocalWitnessLogTimeMetric,
		"The time (in seconds) that it takes to witness log inside sign local.",
		nil,
	)
}

func newAnchorWriteSignLocalStoreTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignLocalStoreTimeMetric,
		"The time (in seconds) that it takes to store inside sign local.",
		nil,
	)
}

func newAnchorWriteSignLocalWatchTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteSignLocalWatchTimeMetric,
		"The time (in seconds) that it takes to watxch inside sign local.",
		nil,
	)
}

func newAnchorWriteResolveHostMetaLinkTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteResolveHostMetaLinkTimeMetric,
		"The time (in seconds) that it takes to resolve host meta link.",
		nil,
	)
}

func newOpQueueAddOperationTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueAddOperationTimeMetric,
		"The time (in seconds) that it takes to add an operation to the queue.",
		nil,
	)
}

func newOpQueueBatchCutTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchCutTimeMetric,
		"The time (in seconds) that it takes to cut an operation batch. The duration is from the time that the first "+
			"operation was added to the time that the batch was cut.",
		nil,
	)
}

func newOpQueueBatchRollbackTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchRollbackTimeMetric,
		"The time (in seconds) that it takes to roll back an operation batch (in case of a transient error). "+
			"The duration is from the time that the first operation was added to the time that the batch was cut.",
		nil,
	)
}

func newOpQueueBatchSize() prometheus.Gauge {
	return newGauge(
		operationQueue, opQueueBatchSizeMetric,
		"The size of a cut batch.",
	)
}

func newObserverProcessAnchorTime() prometheus.Histogram {
	return newHistogram(
		observer, observerProcessAnchorTimeMetric,
		"The time (in seconds) that it takes for the Observer to process an anchor credential.",
		nil,
	)
}

func newObserverProcessDIDTime() prometheus.Histogram {
	return newHistogram(
		observer, observerProcessDIDTimeMetric,
		"The time (in seconds) that it takes for the Observer to process a DID.",
		nil,
	)
}

func newCASWriteTime() prometheus.Histogram {
	return newHistogram(
		cas, casWriteTimeMetric,
		"The time (in seconds) that it takes to write a document to CAS.",
		nil,
	)
}

func newCASResolveTime() prometheus.Histogram {
	return newHistogram(
		cas, casResolveTimeMetric,
		"The time (in seconds) that it takes to resolve a document from CAS.",
		nil,
	)
}

func newCASCacheHitCount() prometheus.Counter {
	return newCounter(
		cas, casCacheHitCountMetric,
		"The number of times a CAS document was retrieved from the cache.",
		nil,
	)
}

func newCASReadTimes() map[string]prometheus.Histogram {
	times := make(map[string]prometheus.Histogram)

	for _, casType := range []string{"local", "ipfs"} {
		times[casType] = newHistogram(
			cas, casReadTimeMetric,
			"The time (in seconds) that it takes to read a document from the CAS storage.",
			prometheus.Labels{"type": casType},
		)
	}

	return times
}

func newDocCreateUpdateTime() prometheus.Histogram {
	return newHistogram(
		document, docCreateUpdateTimeMetric,
		"The time (in seconds) it takes the REST handler to process a create/update operation.",
		nil,
	)
}

func newDocResolveTime() prometheus.Histogram {
	return newHistogram(
		document, docResolveTimeMetric,
		"The time (in seconds) it takes the REST handler to resolve a document.",
		nil,
	)
}

func newDBPutTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbPutTimeMetric,
			"The time (in seconds) it takes the DB to store data.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetTimeMetric,
			"The time (in seconds) it takes the DB to get data.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetTagsTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetTagsTimeMetric,
			"The time (in seconds) it takes the DB to get tags.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBGetBulkTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbGetBulkTimeMetric,
			"The time (in seconds) it takes the DB to get bulk.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBQueryTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbQueryTimeMetric,
			"The time (in seconds) it takes the DB to query.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBDeleteTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbDeleteTimeMetric,
			"The time (in seconds) it takes the DB to delete.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newDBBatchTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			db, dbBatchTimeMetric,
			"The time (in seconds) it takes the DB to batch.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newVCTWitnessAddProofVCTNilTime() prometheus.Histogram {
	return newHistogram(
		vct, vctWitnessAddProofVCTNilTimeMetric,
		"The time (in seconds) it takes the add proof when vct is nil in witness.",
		nil,
	)
}

func newVCTWitnessAddVCTime() prometheus.Histogram {
	return newHistogram(
		vct, vctWitnessAddVCTimeMetric,
		"The time (in seconds) it takes the add vc in witness.",
		nil,
	)
}

func newVCTWitnessAddProofTime() prometheus.Histogram {
	return newHistogram(
		vct, vctWitnessAddProofTimeMetric,
		"The time (in seconds) it takes the add proof in witness.",
		nil,
	)
}

func newVCTWitnessWebFingerTime() prometheus.Histogram {
	return newHistogram(
		vct, vctWitnessWebFingerTimeMetric,
		"The time (in seconds) it takes web finger in witness.",
		nil,
	)
}

func newVCTWitnessVerifyVCTTime() prometheus.Histogram {
	return newHistogram(
		vct, vctWitnessVerifyVCTTimeMetric,
		"The time (in seconds) it takes verify vct signature in witness.",
		nil,
	)
}

func newVCTAddProofParseCredentialTime() prometheus.Histogram {
	return newHistogram(
		vct, vctAddProofParseCredentialTimeMetric,
		"The time (in seconds) it takes the parse credential in add proof.",
		nil,
	)
}

func newVCTAddProofSignTime() prometheus.Histogram {
	return newHistogram(
		vct, vctAddProofSignTimeMetric,
		"The time (in seconds) it takes the sign in add proof.",
		nil,
	)
}

func newSignerGetKeyTime() prometheus.Histogram {
	return newHistogram(
		signer, signerGetKeyTimeMetric,
		"The time (in seconds) it takes the signer to get key.",
		nil,
	)
}

func newSignerSignTime() prometheus.Histogram {
	return newHistogram(
		signer, signerSignMetric,
		"The time (in seconds) it takes the signer to sign.",
		nil,
	)
}

func newSignerAddLinkedDataProofTime() prometheus.Histogram {
	return newHistogram(
		signer, signerAddLinkedDataProofMetric,
		"The time (in seconds) it takes the signer to add data linked prrof.",
		nil,
	)
}

func newResolverResolveDocumentLocallyTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverResolveDocumentLocallyTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document locally.",
		nil,
	)
}

func newResolverGetAnchorOriginEndpointTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverGetAnchorOriginEndpointTimeMetric,
		"The time (in seconds) it takes the resolver to get endpoint information from anchor origin.",
		nil,
	)
}

func newResolverResolveDocumentFromAnchorOriginTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverResolveDocumentFromAnchorOriginTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document from anchor origin.",
		nil,
	)
}

func newResolverResolveDocumentFromCreateStoreTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverResolveDocumentFromCreateStoreTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document from create document store.",
		nil,
	)
}

func newResolverDeleteDocumentFromCreateStoreTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverDeleteDocumentFromCreateStoreTimeMetric,
		"The time (in seconds) it takes the resolver to delete document from create document store.",
		nil,
	)
}

func newResolverVerifyCIDTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverVerifyCIDTimeMetric,
		"The time (in seconds) it takes the resolver to verify CID in anchor graph.",
		nil,
	)
}

func newResolverRequestDiscoveryTime() prometheus.Histogram {
	return newHistogram(
		resolver, resolverRequestDiscoveryTimeMetric,
		"The time (in seconds) it takes the resolver to request DID discovery.",
		nil,
	)
}

func newDecoratorDecorateTime() prometheus.Histogram {
	return newHistogram(
		decorator, decoratorDecorateTimeMetric,
		"The time (in seconds) it takes the decorator to pre-process document operation.",
		nil,
	)
}

func newDecoratorProcessorResolveTime() prometheus.Histogram {
	return newHistogram(
		decorator, decoratorProcessorResolveTimeMetric,
		"The time (in seconds) it takes the processor to resolve document before accepting document operation.",
		nil,
	)
}

func newDecoratorGetAOEndpointAndResolveFromAOTime() prometheus.Histogram {
	return newHistogram(
		decorator, decoratorGetAOEndpointAndResolveFromAOTimeMetric,
		"The time (in seconds) it takes to resolve document from anchor origin before accepting document operation.",
		nil,
	)
}

func newUnpublishedPutOperationTime() prometheus.Histogram {
	return newHistogram(
		operations, unpublishedPutOperationTimeMetric,
		"The time (in seconds) it takes to store unpublished operation.",
		nil,
	)
}

func newUnpublishedGetOperationsTime() prometheus.Histogram {
	return newHistogram(
		operations, unpublishedGetOperationsTimeMetric,
		"The time (in seconds) it takes to get unpublished operations for suffix.",
		nil,
	)
}

func newUnpublishedCalculateKeyTime() prometheus.Histogram {
	return newHistogram(
		operations, unpublishedCalculateOperationKeyTimeMetric,
		"The time (in seconds) it takes to calculate key for unpublished operation.",
		nil,
	)
}

func newPublishedPutOperationsTime() prometheus.Histogram {
	return newHistogram(
		operations, publishedPutOperationsTimeMetric,
		"The time (in seconds) it takes to store published operations.",
		nil,
	)
}

func newPublishedGetOperationsTime() prometheus.Histogram {
	return newHistogram(
		operations, publishedGetOperationsTimeMetric,
		"The time (in seconds) it takes to get published operations for suffix.",
		nil,
	)
}

func newCoreProcessOperationTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreProcessOperationTimeMetrics,
		"The time (in seconds) it takes to process did operation(core).",
		nil,
	)
}

func newCoreGetProtocolVersionTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreGetProtocolVersionTimeMetrics,
		"The time (in seconds) it takes to get protocol version in process operation(core).",
		nil,
	)
}

func newCoreParseOperationTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreParseOperationTimeMetrics,
		"The time (in seconds) it takes to parse operation in process operation(core).",
		nil,
	)
}

func newCoreValidateOperationTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreValidateOperationTimeMetrics,
		"The time (in seconds) it takes to validate operation in process operation(core).",
		nil,
	)
}

func newCoreDecorateOperationTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreDecorateOperationTimeMetrics,
		"The time (in seconds) it takes to decorate operation in process operation(core).",
		nil,
	)
}

func newCoreAddUnpublishedOperationTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreAddUnpublishedOperationTimeMatrix,
		"The time (in seconds) it takes to add unpublished operation to store in process operation(core).",
		nil,
	)
}

func newCoreAddOperationToBatchTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreAddOperationToBatchTimeMatrix,
		"The time (in seconds) it takes to add operation to batch in process operation(core).",
		nil,
	)
}

func newCoreGetCreateOperationResultTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreGetCreateOperationResult,
		"The time (in seconds) it takes to get create operation result in process operation(core).",
		nil,
	)
}

func newCoreHTTPCreateUpdateTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreHTTPCreateUpdateTimeMetrics,
		"The time (in seconds) it takes for create update http call.",
		nil,
	)
}

func newCoreHTTPResolveTime() prometheus.Histogram {
	return newHistogram(
		coreOperations, coreHTTPResolveTimeMetrics,
		"The time (in seconds) it takes for resolve http call.",
		nil,
	)
}

func newAMQPOpenPublisherChannelTime() prometheus.Histogram {
	return newHistogram(
		amqp, amqpOpenPublisherChannelMetric,
		"The time (in seconds) it takes to open an AMQP channel.",
		nil,
	)
}

func newAMQPClosePublisherChannelTime() prometheus.Histogram {
	return newHistogram(
		amqp, amqpClosePublisherChannelMetric,
		"The time (in seconds) it takes to close an AMQP channel.",
		nil,
	)
}
