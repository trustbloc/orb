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
func (m *MetricsProvider) InboxHandlerTime(activityType string, value time.Duration) {
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (m *MetricsProvider) WriteAnchorTime(value time.Duration) {
}

// WriteAnchorBuildCredentialTime records the time it takes to build credential inside write anchor.
func (m *MetricsProvider) WriteAnchorBuildCredentialTime(value time.Duration) {
}

// WriteAnchorGetWitnessesTime records the time it takes to get witnesses inside write anchor.
func (m *MetricsProvider) WriteAnchorGetWitnessesTime(value time.Duration) {
}

// WriteAnchorSignCredentialTime records the time it takes to sign credential inside write anchor.
func (m *MetricsProvider) WriteAnchorSignCredentialTime(value time.Duration) {
}

// WriteAnchorPostOfferActivityTime records the time it takes to post offer activity inside write anchor.
func (m *MetricsProvider) WriteAnchorPostOfferActivityTime(value time.Duration) {
}

// WriteAnchorGetPreviousAnchorsGetBulkTime records the time it takes to get bulk inside previous anchor.
func (m *MetricsProvider) WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration) {
}

// WriteAnchorGetPreviousAnchorsTime records the time it takes to get previous anchor.
func (m *MetricsProvider) WriteAnchorGetPreviousAnchorsTime(value time.Duration) {
}

// WriteAnchorSignWithLocalWitnessTime records the time it takes to sign with local witness.
func (m *MetricsProvider) WriteAnchorSignWithLocalWitnessTime(value time.Duration) {
}

// WriteAnchorSignWithServerKeyTime records the time it takes to sign with server key.
func (m *MetricsProvider) WriteAnchorSignWithServerKeyTime(value time.Duration) {
}

// WriteAnchorSignLocalWitnessLogTime records the time it takes to witness log inside sign local.
func (m *MetricsProvider) WriteAnchorSignLocalWitnessLogTime(value time.Duration) {
}

// WriteAnchorStoreTime records the time it takes to store inside sign local.
func (m *MetricsProvider) WriteAnchorStoreTime(value time.Duration) {
}

// WriteAnchorSignLocalWatchTime records the time it takes to watch inside sign local.
func (m *MetricsProvider) WriteAnchorSignLocalWatchTime(value time.Duration) {
}

// WriteAnchorResolveHostMetaLinkTime records the time it takes to resolve host meta link.
func (m *MetricsProvider) WriteAnchorResolveHostMetaLinkTime(value time.Duration) {
}

// ProcessWitnessedAnchorCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (m *MetricsProvider) ProcessWitnessedAnchorCredentialTime(value time.Duration) {
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

// WitnessAnchorCredentialTime records the time it takes for a verifiable credential to gather proofs from all
// required witnesses (according to witness policy). The start time is when the verifiable credential is issued
// and the end time is the time that the witness policy is satisfied.
func (m *MetricsProvider) WitnessAnchorCredentialTime(value time.Duration) {
}

// DocumentCreateUpdateTime records the time it takes the REST handler to process a create/update operation.
func (m *MetricsProvider) DocumentCreateUpdateTime(value time.Duration) {
}

// DocumentResolveTime records the time it takes the REST handler to resolve a document.
func (m *MetricsProvider) DocumentResolveTime(value time.Duration) {
}

// OutboxIncrementActivityCount increments the number of activities of the given type posted to the outbox.
func (m *MetricsProvider) OutboxIncrementActivityCount(activityType string) {
}

// CASIncrementCacheHitCount increments the number of CAS cache hits.
func (m *MetricsProvider) CASIncrementCacheHitCount() {
}

// CASReadTime records the time it takes to read a document from CAS storage.
func (m *MetricsProvider) CASReadTime(casType string, value time.Duration) {
}

// BatchSize records the size of an operation batch.
func (m *MetricsProvider) BatchSize(float64) {
}

// WitnessAddProofVctNil records vct witness.
func (m *MetricsProvider) WitnessAddProofVctNil(value time.Duration) {
}

// WitnessAddVC records vct witness add vc.
func (m *MetricsProvider) WitnessAddVC(value time.Duration) {
}

// WitnessAddProof records vct witness add proof.
func (m *MetricsProvider) WitnessAddProof(value time.Duration) {
}

// WitnessWebFinger records vct witness web finger.
func (m *MetricsProvider) WitnessWebFinger(value time.Duration) {
}

// WitnessVerifyVCTSignature records vct witness verify vct.
func (m *MetricsProvider) WitnessVerifyVCTSignature(value time.Duration) {
}

// AddProofParseCredential records vct parse credential in add proof.
func (m *MetricsProvider) AddProofParseCredential(value time.Duration) {
}

// AddProofSign records vct sign in add proof.
func (m *MetricsProvider) AddProofSign(value time.Duration) {
}

// SignerGetKey records get key time.
func (m *MetricsProvider) SignerGetKey(value time.Duration) {
}

// SignerSign records sign time.
func (m *MetricsProvider) SignerSign(value time.Duration) {
}

// SignerAddLinkedDataProof records add data linked proof.
func (m *MetricsProvider) SignerAddLinkedDataProof(value time.Duration) {
}

// ResolveDocumentLocallyTime records resolving document locally.
func (m *MetricsProvider) ResolveDocumentLocallyTime(value time.Duration) {
}

// GetAnchorOriginEndpointTime records getting anchor origin endpoint information.
func (m *MetricsProvider) GetAnchorOriginEndpointTime(value time.Duration) {
}

// ResolveDocumentFromAnchorOriginTime records resolving document from anchor origin.
func (m *MetricsProvider) ResolveDocumentFromAnchorOriginTime(value time.Duration) {
}

// DeleteDocumentFromCreateDocumentStoreTime records deleting document from create document store.
func (m *MetricsProvider) DeleteDocumentFromCreateDocumentStoreTime(value time.Duration) {
}

// ResolveDocumentFromCreateDocumentStoreTime records resolving document from create document store.
func (m *MetricsProvider) ResolveDocumentFromCreateDocumentStoreTime(value time.Duration) {
}

// VerifyCIDTime records verifying CID for document resolution.
func (m *MetricsProvider) VerifyCIDTime(value time.Duration) {
}

// RequestDiscoveryTime records the time it takes to request discovery.
func (m *MetricsProvider) RequestDiscoveryTime(value time.Duration) {
}

// DecorateTime records the time it takes to decorate operation (for update handler).
func (m *MetricsProvider) DecorateTime(value time.Duration) {
}

// ProcessorResolveTime records the time it takes for processor to resolve document
// when decorating operation (for update handler).
func (m *MetricsProvider) ProcessorResolveTime(value time.Duration) {
}

// GetAOEndpointAndResolveDocumentFromAOTime records the time it takes to get anchor origin endpoint
// and resolve document from anchor origin when decorating operation (for update handler).
func (m *MetricsProvider) GetAOEndpointAndResolveDocumentFromAOTime(value time.Duration) {
}

// PutUnpublishedOperation records the time it takes to store unpublished operation.
func (m *MetricsProvider) PutUnpublishedOperation(value time.Duration) {
}

// GetUnpublishedOperations records the time it takes to get unpublished operations for suffix.
func (m *MetricsProvider) GetUnpublishedOperations(value time.Duration) {
}

// CalculateUnpublishedOperationKey records the time to create unpublished operation key.
func (m *MetricsProvider) CalculateUnpublishedOperationKey(value time.Duration) {
}

// PutPublishedOperations records the time to store published operations.
func (m *MetricsProvider) PutPublishedOperations(value time.Duration) {
}

// GetPublishedOperations records the time to get published operations for suffix.
func (m *MetricsProvider) GetPublishedOperations(value time.Duration) {
}
