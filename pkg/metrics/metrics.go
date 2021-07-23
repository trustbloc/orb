/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "orb"

	activityPub                = "activitypub"
	apPostTimeMetric           = "outbox_post_time"
	apResolveInboxesTimeMetric = "outbox_resolve_inboxes_time"
	apInboxHandlerTimeMetric   = "inbox_handler_time"
)

// Metrics manages the metrics for Orb.
type Metrics struct {
	apOutboxPostTime           prometheus.Histogram
	apOutboxResolveInboxesTime prometheus.Histogram
	apInboxHandlerTime         prometheus.Histogram
}

// New returns a new Orb metrics provider.
func New() *Metrics {
	m := &Metrics{
		apOutboxPostTime: newHistogram(
			activityPub, apPostTimeMetric,
			"The time (in seconds) that it takes to post a message to the outbox",
		),
		apOutboxResolveInboxesTime: newHistogram(
			activityPub, apResolveInboxesTimeMetric,
			"The time (in seconds) that it takes to resolve the inboxes of the destinations when posting to the outbox",
		),
		apInboxHandlerTime: newHistogram(
			activityPub, apInboxHandlerTimeMetric,
			"The time (in seconds) that it takes to handle an activity posted to the inbox",
		),
	}

	prometheus.MustRegister(
		m.apOutboxPostTime,
		m.apOutboxResolveInboxesTime,
		m.apInboxHandlerTime,
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
