/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import "time"

// MetricsProvider implements a mock ActivityPub metrics provider.
type MetricsProvider struct{}

// OutboxPostTime records the time it takes to post a message to the outbox.
func (m *MetricsProvider) OutboxPostTime(value time.Duration) {
}

// OutboxResolveInboxesTime records the time it takes to resolve inboxes for an outbox post.
func (m *MetricsProvider) OutboxResolveInboxesTime(value time.Duration) {
}

// InboxHandlerTime records the time it takes to handle an activity posted to the inbox.
func (m *MetricsProvider) InboxHandlerTime(value time.Duration) {
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (m *MetricsProvider) WriteAnchorTime(value time.Duration) {
}

// ProcessWitnessedAnchoredCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (m *MetricsProvider) ProcessWitnessedAnchoredCredentialTime(value time.Duration) {
}
