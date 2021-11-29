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
	opQueueBatchAckTimeMetric      = "batch_ack_seconds"
	opQueueBatchNackTimeMetric     = "batch_nack_seconds"
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
	opqueueBatchAckTime      prometheus.Histogram
	opqueueBatchNackTime     prometheus.Histogram
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
		apOutboxPostTime:                         newOutboxPostTime(),
		apOutboxResolveInboxesTime:               newOutboxResolveInboxesTime(),
		anchorWriteTime:                          newAnchorWriteTime(),
		anchorWriteBuildCredTime:                 newAnchorWriteBuildCredTime(),
		anchorWriteGetWitnessesTime:              newAnchorWriteGetWitnessesTime(),
		anchorWriteSignCredTime:                  newAnchorWriteSignCredTime(),
		anchorWritePostOfferActivityTime:         newAnchorWritePostOfferActivityTime(),
		anchorWriteGetPreviousAnchorsGetBulkTime: newAnchorWriteGetPreviousAnchorsGetBulkTime(),
		anchorWriteGetPreviousAnchorsTime:        newAnchorWriteGetPreviousAnchorsTime(),
		anchorWitnessTime:                        newAnchorWitnessTime(),
		anchorProcessWitnessedTime:               newAnchorProcessWitnessedTime(),
		anchorWriteSignWithLocalWitnessTime:      newAnchorWriteSignWithLocalWitnessTime(),
		anchorWriteSignWithServerKeyTime:         newAnchorWriteSignWithServerKeyTime(),
		anchorWriteSignLocalWitnessLogTime:       newAnchorWriteSignLocalWitnessLogTime(),
		anchorWriteSignLocalStoreTime:            newAnchorWriteSignLocalStoreTime(),
		anchorWriteSignLocalWatchTime:            newAnchorWriteSignLocalWatchTime(),
		anchorWriteResolveHostMetaLinkTime:       newAnchorWriteResolveHostMetaLinkTime(),
		opqueueAddOperationTime:                  newOpQueueAddOperationTime(),
		opqueueBatchCutTime:                      newOpQueueBatchCutTime(),
		opqueueBatchRollbackTime:                 newOpQueueBatchRollbackTime(),
		opqueueBatchAckTime:                      newOpQueueBatchAckTime(),
		opqueueBatchNackTime:                     newOpQueueBatchNackTime(),
		opqueueBatchSize:                         newOpQueueBatchSize(),
		observerProcessAnchorTime:                newObserverProcessAnchorTime(),
		observerProcessDIDTime:                   newObserverProcessDIDTime(),
		casWriteTime:                             newCASWriteTime(),
		casResolveTime:                           newCASResolveTime(),
		casReadTimes:                             newCASReadTimes(),
		casCacheHitCount:                         newCASCacheHitCount(),
		docCreateUpdateTime:                      newDocCreateUpdateTime(),
		docResolveTime:                           newDocResolveTime(),
		apInboxHandlerTimes:                      newInboxHandlerTimes(activityTypes),
		apOutboxActivityCounts:                   newOutboxActivityCounts(activityTypes),
		dbPutTimes:                               newDBPutTime(dbTypes),
		dbGetTimes:                               newDBGetTime(dbTypes),
		dbGetTagsTimes:                           newDBGetTagsTime(dbTypes),
		dbGetBulkTimes:                           newDBGetBulkTime(dbTypes),
		dbQueryTimes:                             newDBQueryTime(dbTypes),
		dbDeleteTimes:                            newDBDeleteTime(dbTypes),
		dbBatchTimes:                             newDBBatchTime(dbTypes),
		vctWitnessAddProofVCTNilTimes:            newVCTWitnessAddProofVCTNilTime(),
		vctWitnessAddVCTimes:                     newVCTWitnessAddVCTime(),
		vctWitnessAddProofTimes:                  newVCTWitnessAddProofTime(),
		vctWitnessAddWebFingerTimes:              newVCTWitnessWebFingerTime(),
		vctWitnessVerifyVCTimes:                  newVCTWitnessVerifyVCTTime(),
		vctAddProofParseCredentialTimes:          newVCTAddProofParseCredentialTime(),
		vctAddProofSignTimes:                     newVCTAddProofSignTime(),
		signerGetKeyTimes:                        newSignerGetKeyTime(),
		signerSignTimes:                          newSignerSignTime(),
		signerAddLinkedDataProofTimes:            newSignerAddLinkedDataProofTime(),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime, m.apOutboxResolveInboxesTime,
		m.anchorWriteTime, m.anchorWitnessTime, m.anchorProcessWitnessedTime, m.anchorWriteBuildCredTime,
		m.anchorWriteGetWitnessesTime, m.anchorWriteSignCredTime, m.anchorWritePostOfferActivityTime,
		m.anchorWriteGetPreviousAnchorsGetBulkTime, m.anchorWriteGetPreviousAnchorsTime,
		m.anchorWriteSignWithLocalWitnessTime, m.anchorWriteSignWithServerKeyTime, m.anchorWriteSignLocalWitnessLogTime,
		m.anchorWriteSignLocalStoreTime, m.anchorWriteSignLocalWatchTime,
		m.opqueueAddOperationTime, m.opqueueBatchCutTime, m.opqueueBatchRollbackTime,
		m.opqueueBatchAckTime, m.opqueueBatchNackTime, m.opqueueBatchSize,
		m.observerProcessAnchorTime, m.observerProcessDIDTime,
		m.casWriteTime, m.casResolveTime, m.casCacheHitCount,
		m.docCreateUpdateTime, m.docResolveTime,
		m.vctWitnessAddProofVCTNilTimes, m.vctWitnessAddVCTimes, m.vctWitnessAddProofTimes,
		m.vctWitnessAddWebFingerTimes, m.vctWitnessVerifyVCTimes, m.vctAddProofParseCredentialTimes,
		m.vctAddProofSignTimes, m.signerSignTimes, m.signerGetKeyTimes, m.signerAddLinkedDataProofTimes,
		m.anchorWriteResolveHostMetaLinkTime,
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

// BatchAckTime records the time to acknowledge all of the operations that are removed from the queue.
func (m *Metrics) BatchAckTime(value time.Duration) {
	m.opqueueBatchAckTime.Observe(value.Seconds())

	logger.Debugf("BatchAck time: %s", value)
}

// BatchNackTime records the time to nack all of the operations that are to be placed back on the queue.
func (m *Metrics) BatchNackTime(value time.Duration) {
	m.opqueueBatchNackTime.Observe(value.Seconds())

	logger.Debugf("BatchNack time: %s", value)
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

// SignerSign records sign.
func (m *Metrics) SignerSign(value time.Duration) {
	m.signerSignTimes.Observe(value.Seconds())

	logger.Debugf("signer sign time: %s", value)
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

func newOpQueueBatchAckTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchAckTimeMetric,
		"The time (in seconds) that it takes to acknowledge all of the operations that are removed from the queue.",
		nil,
	)
}

func newOpQueueBatchNackTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchNackTimeMetric,
		"The time (in seconds) that it takes to nack all of the operations that are to be placed back on the queue.",
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
