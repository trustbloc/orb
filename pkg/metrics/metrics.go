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
	activityPub                = "activitypub"
	apPostTimeMetric           = "outbox_post_seconds"
	apResolveInboxesTimeMetric = "outbox_resolve_inboxes_seconds"
	apInboxHandlerTimeMetric   = "inbox_handler_seconds"

	// Anchor.
	anchor                       = "anchor"
	anchorWriteTimeMetric        = "write_seconds"
	anchorWitnessMetric          = "witness_seconds"
	anchorProcessWitnessedMetric = "process_witnessed_seconds"

	// Operation queue.
	operationQueue                 = "opqueue"
	opQueueAddOperationTimeMetric  = "add_operation_seconds"
	opQueueBatchCutTimeMetric      = "batch_cut_seconds"
	opQueueBatchRollbackTimeMetric = "batch_rollback_seconds"
	opQueueBatchAckTimeMetric      = "batch_ack_seconds"
	opQueueBatchNackTimeMetric     = "batch_nack_seconds"

	// Observer.
	observer                        = "observer"
	observerProcessAnchorTimeMetric = "process_anchor_seconds"
	observerProcessDIDTimeMetric    = "process_did_seconds"

	// CAS.
	cas                  = "cas"
	casWriteTimeMetric   = "cas_write_seconds"
	casResolveTimeMetric = "cas_resolve_seconds"

	// Document handler.
	document                  = "document"
	docCreateUpdateTimeMetric = "create_update_seconds"
	docResolveTimeMetric      = "resolve_seconds"
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
	apInboxHandlerTime         prometheus.Histogram

	anchorWriteTime            prometheus.Histogram
	anchorWitnessTime          prometheus.Histogram
	anchorProcessWitnessedTime prometheus.Histogram

	opqueueAddOperationTime  prometheus.Histogram
	opqueueBatchCutTime      prometheus.Histogram
	opqueueBatchRollbackTime prometheus.Histogram
	opqueueBatchAckTime      prometheus.Histogram
	opqueueBatchNackTime     prometheus.Histogram

	observerProcessAnchorTime prometheus.Histogram
	observerProcessDIDTime    prometheus.Histogram

	casWriteTime   prometheus.Histogram
	casResolveTime prometheus.Histogram

	docCreateUpdateTime prometheus.Histogram
	docResolveTime      prometheus.Histogram
}

// Get returns an Orb metrics provider.
func Get() *Metrics {
	createOnce.Do(func() {
		instance = newMetrics()
	})

	return instance
}

func newMetrics() *Metrics {
	m := &Metrics{
		apOutboxPostTime:           newOutboxPostTime(),
		apOutboxResolveInboxesTime: newOutboxResolveInboxesTime(),
		apInboxHandlerTime:         newInboxHandlerTime(),
		anchorWriteTime:            newAnchorWriteTime(),
		anchorWitnessTime:          newAnchorWitnessTime(),
		anchorProcessWitnessedTime: newAnchorProcessWitnessedTime(),
		opqueueAddOperationTime:    newOpQueueAddOperationTime(),
		opqueueBatchCutTime:        newOpQueueBatchCutTime(),
		opqueueBatchRollbackTime:   newOpQueueBatchRollbackTime(),
		opqueueBatchAckTime:        newOpQueueBatchAckTime(),
		opqueueBatchNackTime:       newOpQueueBatchNackTime(),
		observerProcessAnchorTime:  newObserverProcessAnchorTime(),
		observerProcessDIDTime:     newObserverProcessDIDTime(),
		casWriteTime:               newCASWriteTime(),
		casResolveTime:             newCASResolveTime(),
		docCreateUpdateTime:        newDocCreateUpdateTime(),
		docResolveTime:             newDocResolveTime(),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime, m.apOutboxResolveInboxesTime, m.apInboxHandlerTime,
		m.anchorWriteTime, m.anchorWitnessTime, m.anchorProcessWitnessedTime,
		m.opqueueAddOperationTime, m.opqueueBatchCutTime, m.opqueueBatchRollbackTime,
		m.observerProcessAnchorTime, m.observerProcessDIDTime, m.casWriteTime, m.casResolveTime,
		m.opqueueBatchAckTime, m.opqueueBatchNackTime, m.docCreateUpdateTime, m.docResolveTime,
	)

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
func (m *Metrics) InboxHandlerTime(value time.Duration) {
	m.apInboxHandlerTime.Observe(value.Seconds())

	logger.Debugf("InboxHandler time: %s", value)
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (m *Metrics) WriteAnchorTime(value time.Duration) {
	m.anchorWriteTime.Observe(value.Seconds())

	logger.Infof("WriteAnchor time: %s", value)
}

// WitnessAnchorCredentialTime records the time it takes for a verifiable credential to gather proofs from all
// required witnesses (according to witness policy). The start time is when the verifiable credential is issued
// and the end time is the time that the witness policy is satisfied.
func (m *Metrics) WitnessAnchorCredentialTime(value time.Duration) {
	m.anchorWitnessTime.Observe(value.Seconds())

	logger.Infof("WitnessAnchorCredential time: %s", value)
}

// ProcessWitnessedAnchorCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (m *Metrics) ProcessWitnessedAnchorCredentialTime(value time.Duration) {
	m.anchorProcessWitnessedTime.Observe(value.Seconds())

	logger.Infof("ProcessWitnessedAnchorCredential time: %s", value)
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

func newCounter(subsystem, name, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
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

func newHistogram(subsystem, name, help string) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      name,
		Help:      help,
	})
}

func newOutboxPostTime() prometheus.Histogram {
	return newHistogram(
		activityPub, apPostTimeMetric,
		"The time (in seconds) that it takes to post a message to the outbox.",
	)
}

func newOutboxResolveInboxesTime() prometheus.Histogram {
	return newHistogram(
		activityPub, apResolveInboxesTimeMetric,
		"The time (in seconds) that it takes to resolve the inboxes of the destinations when posting to the outbox.",
	)
}

func newInboxHandlerTime() prometheus.Histogram {
	return newHistogram(
		activityPub, apInboxHandlerTimeMetric,
		"The time (in seconds) that it takes to handle an activity posted to the inbox.",
	)
}

func newAnchorWriteTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWriteTimeMetric,
		"The time (in seconds) that it takes to write an anchor credential and post an 'Offer' activity.",
	)
}

func newAnchorWitnessTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorWitnessMetric,
		"The time (in seconds) that it takes for a verifiable credential to gather proofs from all required "+
			"witnesses (according to witness policy). The start time is when the verifiable credential is issued "+
			"and the end time is the time that the witness policy is satisfied.",
	)
}

func newAnchorProcessWitnessedTime() prometheus.Histogram {
	return newHistogram(
		anchor, anchorProcessWitnessedMetric,
		"The time (in seconds) that it takes to process a witnessed anchor credential by publishing it to "+
			"the Observer and posting a 'Create' activity.",
	)
}

func newOpQueueAddOperationTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueAddOperationTimeMetric,
		"The time (in seconds) that it takes to add an operation to the queue.",
	)
}

func newOpQueueBatchCutTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchCutTimeMetric,
		"The time (in seconds) that it takes to cut an operation batch. The duration is from the time that the first "+
			"operation was added to the time that the batch was cut.",
	)
}

func newOpQueueBatchRollbackTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchRollbackTimeMetric,
		"The time (in seconds) that it takes to roll back an operation batch (in case of a transient error). "+
			"The duration is from the time that the first operation was added to the time that the batch was cut.",
	)
}

func newOpQueueBatchAckTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchAckTimeMetric,
		"The time (in seconds) that it takes to acknowledge all of the operations that are removed from the queue.",
	)
}

func newOpQueueBatchNackTime() prometheus.Histogram {
	return newHistogram(
		operationQueue, opQueueBatchNackTimeMetric,
		"The time (in seconds) that it takes to nack all of the operations that are to be placed back on the queue.",
	)
}

func newObserverProcessAnchorTime() prometheus.Histogram {
	return newHistogram(
		observer, observerProcessAnchorTimeMetric,
		"The time (in seconds) that it takes for the Observer to process an anchor credential.",
	)
}

func newObserverProcessDIDTime() prometheus.Histogram {
	return newHistogram(
		observer, observerProcessDIDTimeMetric,
		"The time (in seconds) that it takes for the Observer to process a DID.",
	)
}

func newCASWriteTime() prometheus.Histogram {
	return newHistogram(
		cas, casWriteTimeMetric,
		"The time (in seconds) that it takes to write a document to CAS.",
	)
}

func newCASResolveTime() prometheus.Histogram {
	return newHistogram(
		cas, casResolveTimeMetric,
		"The time (in seconds) that it takes to resolve a document from CAS.",
	)
}

func newDocCreateUpdateTime() prometheus.Histogram {
	return newHistogram(
		document, docCreateUpdateTimeMetric,
		"The time (in seconds) it takes the REST handler to process a create/update operation.",
	)
}

func newDocResolveTime() prometheus.Histogram {
	return newHistogram(
		document, docResolveTimeMetric,
		"The time (in seconds) it takes the REST handler to resolve a document.",
	)
}
