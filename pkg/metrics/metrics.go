/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	anchorProcessWitnessedMetric = "process_witnessed_seconds"

	// Operation queue.
	operationQueue                 = "opqueue"
	opQueueAddOperationTimeMetric  = "add_operation_seconds"
	opQueueBatchCutTimeMetric      = "batch_cut_seconds"
	opQueueBatchRollbackTimeMetric = "batch_rollback_seconds"

	// Observer.
	observer                        = "observer"
	observerProcessAnchorTimeMetric = "process_anchor_seconds"
	observerProcessDIDTimeMetric    = "process_did_seconds"
)

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
	anchorProcessWitnessedTime prometheus.Histogram

	opqueueAddOperationTime  prometheus.Histogram
	opqueueBatchCutTime      prometheus.Histogram
	opqueueBatchRollbackTime prometheus.Histogram

	observerProcessAnchorTime prometheus.Histogram
	observerProcessDIDTime    prometheus.Histogram
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
		apOutboxPostTime: newHistogram(
			activityPub, apPostTimeMetric,
			"The time (in seconds) that it takes to post a message to the outbox.",
		),
		apOutboxResolveInboxesTime: newHistogram(
			activityPub, apResolveInboxesTimeMetric,
			"The time (in seconds) that it takes to resolve the inboxes of the destinations when posting to the outbox.",
		),
		apInboxHandlerTime: newHistogram(
			activityPub, apInboxHandlerTimeMetric,
			"The time (in seconds) that it takes to handle an activity posted to the inbox.",
		),
		anchorWriteTime: newHistogram(
			anchor, anchorWriteTimeMetric,
			"The time (in seconds) that it takes to write an anchor credential and post an 'Offer' activity.",
		),
		anchorProcessWitnessedTime: newHistogram(
			anchor, anchorProcessWitnessedMetric,
			"The time (in seconds) that it takes to process a witnessed anchor credential by publishing it to "+
				"the Observer and posting a 'Create' activity.",
		),
		opqueueAddOperationTime: newHistogram(
			operationQueue, opQueueAddOperationTimeMetric,
			"The time (in seconds) that it takes to add an operation to the queue.",
		),
		opqueueBatchCutTime: newHistogram(
			operationQueue, opQueueBatchCutTimeMetric,
			"The time (in seconds) that it takes to cut an operation batch.",
		),
		opqueueBatchRollbackTime: newHistogram(
			operationQueue, opQueueBatchRollbackTimeMetric,
			"The time (in seconds) that it takes to roll back an operation batch.",
		),
		observerProcessAnchorTime: newHistogram(
			observer, observerProcessAnchorTimeMetric,
			"The time (in seconds) that it takes for the Observer to process an anchor credential.",
		),
		observerProcessDIDTime: newHistogram(
			observer, observerProcessDIDTimeMetric,
			"The time (in seconds) that it takes for the Observer to process a DID.",
		),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime,
		m.apOutboxResolveInboxesTime,
		m.apInboxHandlerTime,
		m.anchorWriteTime,
		m.anchorProcessWitnessedTime,
		m.opqueueAddOperationTime,
		m.opqueueBatchCutTime,
		m.opqueueBatchRollbackTime,
		m.observerProcessAnchorTime,
		m.observerProcessDIDTime,
	)

	return m
}

// OutboxPostTime records the time it takes to post a message to the outbox.
func (m *Metrics) OutboxPostTime(value time.Duration) {
	m.apOutboxPostTime.Observe(value.Seconds())
}

// OutboxResolveInboxesTime records the time it takes to resolve inboxes for an outbox post.
func (m *Metrics) OutboxResolveInboxesTime(value time.Duration) {
	m.apOutboxResolveInboxesTime.Observe(value.Seconds())
}

// InboxHandlerTime records the time it takes to handle an activity posted to the inbox.
func (m *Metrics) InboxHandlerTime(value time.Duration) {
	m.apInboxHandlerTime.Observe(value.Seconds())
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (m *Metrics) WriteAnchorTime(value time.Duration) {
	m.anchorWriteTime.Observe(value.Seconds())
}

// ProcessWitnessedAnchoredCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (m *Metrics) ProcessWitnessedAnchoredCredentialTime(value time.Duration) {
	m.anchorProcessWitnessedTime.Observe(value.Seconds())
}

// AddOperationTime records the time it takes to add an operation to the queue.
func (m *Metrics) AddOperationTime(value time.Duration) {
	m.opqueueAddOperationTime.Observe(value.Seconds())
}

// BatchCutTime records the time it takes to cut an operation batch.
func (m *Metrics) BatchCutTime(value time.Duration) {
	m.opqueueBatchCutTime.Observe(value.Seconds())
}

// BatchRollbackTime records the time it takes to roll back an operation batch (in case of a transient error).
func (m *Metrics) BatchRollbackTime(value time.Duration) {
	m.opqueueBatchRollbackTime.Observe(value.Seconds())
}

// ProcessAnchorTime records the time it takes for the Observer to process an anchor credential.
func (m *Metrics) ProcessAnchorTime(value time.Duration) {
	m.observerProcessAnchorTime.Observe(value.Seconds())
}

// ProcessDIDTime records the time it takes for the Observer to process a DID.
func (m *Metrics) ProcessDIDTime(value time.Duration) {
	m.observerProcessDIDTime.Observe(value.Seconds())
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
