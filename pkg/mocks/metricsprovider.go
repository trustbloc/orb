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

// AddOperationTime records the time it takes to add an operation to the queue.
func (m *MetricsProvider) AddOperationTime(value time.Duration) {
}

// BatchCutTime records the time it takes to cut an operation batch.
func (m *MetricsProvider) BatchCutTime(value time.Duration) {
}

// BatchRollbackTime records the time it takes to roll back an operation batch (in case of a transient error).
func (m *MetricsProvider) BatchRollbackTime(value time.Duration) {
}

// ProcessAnchorTime records the time it takes for the Observer to process an anchor credential.
func (m *MetricsProvider) ProcessAnchorTime(value time.Duration) {
}

// ProcessDIDTime records the time it takes for the Observer to process a DID.
func (m *MetricsProvider) ProcessDIDTime(value time.Duration) {
}

// CASWriteTime records the time it takes to write a document to CAS.
func (m *MetricsProvider) CASWriteTime(value time.Duration) {
}

// CASResolveTime records the time it takes to resolve a document from CAS.
func (m *MetricsProvider) CASResolveTime(value time.Duration) {
}
