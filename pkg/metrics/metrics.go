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
	anchor                                 = "anchor"
	anchorWriteTimeMetric                  = "write_seconds"
	anchorWitnessMetric                    = "witness_seconds"
	anchorProcessWitnessedMetric           = "process_witnessed_seconds"
	anchorWriteBuildCredTimeMetric         = "write_build_cred_seconds"
	anchorWriteGetWitnessesTimeMetric      = "write_get_witnesses_seconds"
	anchorWriteSignCredTimeMetric          = "write_sign_cred_seconds"
	anchorWritePostOfferActivityTimeMetric = "write_post_offer_activity_seconds"

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

	anchorWriteTime                  prometheus.Histogram
	anchorWitnessTime                prometheus.Histogram
	anchorProcessWitnessedTime       prometheus.Histogram
	anchorWriteBuildCredTime         prometheus.Histogram
	anchorWriteGetWitnessesTime      prometheus.Histogram
	anchorWriteSignCredTime          prometheus.Histogram
	anchorWritePostOfferActivityTime prometheus.Histogram

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
}

// Get returns an Orb metrics provider.
func Get() *Metrics {
	createOnce.Do(func() {
		instance = newMetrics()
	})

	return instance
}

func newMetrics() *Metrics { //nolint:funlen
	activityTypes := []string{"Create", "Announce", "Offer", "Like", "Follow", "InviteWitness", "Accept", "Reject"}
	dbTypes := []string{"CouchDB"}

	m := &Metrics{
		apOutboxPostTime:                 newOutboxPostTime(),
		apOutboxResolveInboxesTime:       newOutboxResolveInboxesTime(),
		anchorWriteTime:                  newAnchorWriteTime(),
		anchorWriteBuildCredTime:         newAnchorWriteBuildCredTime(),
		anchorWriteGetWitnessesTime:      newAnchorWriteGetWitnessesTime(),
		anchorWriteSignCredTime:          newAnchorWriteSignCredTime(),
		anchorWritePostOfferActivityTime: newAnchorWritePostOfferActivityTime(),
		anchorWitnessTime:                newAnchorWitnessTime(),
		anchorProcessWitnessedTime:       newAnchorProcessWitnessedTime(),

		opqueueAddOperationTime:   newOpQueueAddOperationTime(),
		opqueueBatchCutTime:       newOpQueueBatchCutTime(),
		opqueueBatchRollbackTime:  newOpQueueBatchRollbackTime(),
		opqueueBatchAckTime:       newOpQueueBatchAckTime(),
		opqueueBatchNackTime:      newOpQueueBatchNackTime(),
		opqueueBatchSize:          newOpQueueBatchSize(),
		observerProcessAnchorTime: newObserverProcessAnchorTime(),
		observerProcessDIDTime:    newObserverProcessDIDTime(),
		casWriteTime:              newCASWriteTime(),
		casResolveTime:            newCASResolveTime(),
		casReadTimes:              newCASReadTimes(),
		casCacheHitCount:          newCASCacheHitCount(),
		docCreateUpdateTime:       newDocCreateUpdateTime(),
		docResolveTime:            newDocResolveTime(),
		apInboxHandlerTimes:       newInboxHandlerTimes(activityTypes),
		apOutboxActivityCounts:    newOutboxActivityCounts(activityTypes),
		dbPutTimes:                newDBPutTime(dbTypes),
		dbGetTimes:                newDBGetTime(dbTypes),
		dbGetTagsTimes:            newDBGetTagsTime(dbTypes),
		dbGetBulkTimes:            newDBGetBulkTime(dbTypes),
		dbQueryTimes:              newDBQueryTime(dbTypes),
		dbDeleteTimes:             newDBDeleteTime(dbTypes),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime, m.apOutboxResolveInboxesTime,
		m.anchorWriteTime, m.anchorWitnessTime, m.anchorProcessWitnessedTime, m.anchorWriteBuildCredTime,
		m.anchorWriteGetWitnessesTime, m.anchorWriteSignCredTime, m.anchorWritePostOfferActivityTime,
		m.opqueueAddOperationTime, m.opqueueBatchCutTime, m.opqueueBatchRollbackTime,
		m.opqueueBatchAckTime, m.opqueueBatchNackTime, m.opqueueBatchSize,
		m.observerProcessAnchorTime, m.observerProcessDIDTime,
		m.casWriteTime, m.casResolveTime, m.casCacheHitCount,
		m.docCreateUpdateTime, m.docResolveTime,
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

	logger.Debugf("DB time put [%s]: %s", dbType, value)
}

// DBGetTime records the time it takes to get data in db.
func (m *Metrics) DBGetTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("DB time get [%s]: %s", dbType, value)
}

// DBGetTagsTime records the time it takes to get tags in db.
func (m *Metrics) DBGetTagsTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetTagsTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("DB time get tags [%s]: %s", dbType, value)
}

// DBGetBulkTime records the time it takes to get bulk in db.
func (m *Metrics) DBGetBulkTime(dbType string, value time.Duration) {
	if c, ok := m.dbGetBulkTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("DB time get bulk [%s]: %s", dbType, value)
}

// DBQueryTime records the time it takes to query in db.
func (m *Metrics) DBQueryTime(dbType string, value time.Duration) {
	if c, ok := m.dbQueryTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("DB time query [%s]: %s", dbType, value)
}

// DBDeleteTime records the time it takes to delete in db.
func (m *Metrics) DBDeleteTime(dbType string, value time.Duration) {
	if c, ok := m.dbDeleteTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debugf("DB time delete [%s]: %s", dbType, value)
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
