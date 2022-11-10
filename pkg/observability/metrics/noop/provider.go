/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import (
	"time"

	"github.com/trustbloc/orb/pkg/observability/metrics"
)

// Provider implements a no-op metrics provider.
type Provider struct {
}

// NewProvider creates new instance of Prometheus Metrics Provider.
func NewProvider() *Provider {
	return &Provider{}
}

// Create does nothing.
func (pp *Provider) Create() error {
	return nil
}

// Destroy does nothing.
func (pp *Provider) Destroy() error {
	return nil
}

// Metrics returns supported metrics.
func (pp *Provider) Metrics() metrics.Metrics {
	return &NoOptMetrics{}
}

// NoOptMetrics provides default no operation implementation for the Metrics interface.
type NoOptMetrics struct{}

// CASIncrementCacheHitCount increments the number of CAS cache hits.
func (nm NoOptMetrics) CASIncrementCacheHitCount() {}

// CASWriteTime records the time it takes to write a document to CAS.
func (nm NoOptMetrics) CASWriteTime(value time.Duration) {}

// CASReadTime records the time it takes to read a document from CAS storage.
func (nm NoOptMetrics) CASReadTime(casType string, value time.Duration) {}

// PutPublishedOperations records the time to store published operations.
func (nm NoOptMetrics) PutPublishedOperations(duration time.Duration) {}

// GetPublishedOperations records the time to get published operations for suffix.
func (nm NoOptMetrics) GetPublishedOperations(duration time.Duration) {}

// CASResolveTime records the time it takes to resolve a document from CAS.
func (nm NoOptMetrics) CASResolveTime(value time.Duration) {}

// PutUnpublishedOperation records the time it takes to store unpublished operation.
func (nm NoOptMetrics) PutUnpublishedOperation(duration time.Duration) {}

// GetUnpublishedOperations records the time it takes to get unpublished operations for suffix.
func (nm NoOptMetrics) GetUnpublishedOperations(duration time.Duration) {}

// CalculateUnpublishedOperationKey records the time to create unpublished operation key.
func (nm NoOptMetrics) CalculateUnpublishedOperationKey(duration time.Duration) {}

// SignerSign records sign.
func (nm NoOptMetrics) SignerSign(value time.Duration) {}

// SignerGetKey records get key time.
func (nm NoOptMetrics) SignerGetKey(value time.Duration) {}

// SignerAddLinkedDataProof records add data linked proof.
func (nm NoOptMetrics) SignerAddLinkedDataProof(value time.Duration) {}

// WitnessAnchorCredentialTime records the time it takes for a verifiable credential to gather proofs from all
// required witnesses (according to witness policy). The start time is when the verifiable credential is issued
// and the end time is the time that the witness policy is satisfied.
func (nm NoOptMetrics) WitnessAnchorCredentialTime(duration time.Duration) {}

// WitnessAddProofVctNil records vct witness.
func (nm NoOptMetrics) WitnessAddProofVctNil(value time.Duration) {}

// WitnessAddVC records vct witness add vc.
func (nm NoOptMetrics) WitnessAddVC(value time.Duration) {}

// WitnessAddProof records vct witness add proof.
func (nm NoOptMetrics) WitnessAddProof(value time.Duration) {}

// WitnessWebFinger records vct witness web finger.
func (nm NoOptMetrics) WitnessWebFinger(value time.Duration) {}

// WitnessVerifyVCTSignature records vct witness verify vct.
func (nm NoOptMetrics) WitnessVerifyVCTSignature(value time.Duration) {}

// AddProofParseCredential records vct parse credential in add proof.
func (nm NoOptMetrics) AddProofParseCredential(value time.Duration) {}

// AddProofSign records vct sign in add proof.
func (nm NoOptMetrics) AddProofSign(value time.Duration) {}

// ProcessAnchorTime records the time it takes for the Observer to process an anchor credential.
func (nm NoOptMetrics) ProcessAnchorTime(value time.Duration) {}

// ProcessDIDTime records the time it takes for the Observer to process a DID.
func (nm NoOptMetrics) ProcessDIDTime(value time.Duration) {}

// InboxHandlerTime records the time it takes to handle an activity posted to the inbox.
func (nm NoOptMetrics) InboxHandlerTime(activityType string, value time.Duration) {}

// OutboxPostTime records the time it takes to post a message to the outbox.
func (nm NoOptMetrics) OutboxPostTime(value time.Duration) {}

// OutboxResolveInboxesTime records the time it takes to resolve inboxes for an outbox post.
func (nm NoOptMetrics) OutboxResolveInboxesTime(value time.Duration) {}

// OutboxIncrementActivityCount increments the number of activities of the given type posted to the outbox.
func (nm NoOptMetrics) OutboxIncrementActivityCount(activityType string) {}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (nm NoOptMetrics) WriteAnchorTime(value time.Duration) {}

// WriteAnchorBuildCredentialTime records the time it takes to build credential inside write anchor.
func (nm NoOptMetrics) WriteAnchorBuildCredentialTime(value time.Duration) {}

// WriteAnchorGetWitnessesTime records the time it takes to get witnesses inside write anchor.
func (nm NoOptMetrics) WriteAnchorGetWitnessesTime(value time.Duration) {}

// WriteAnchorStoreTime records the time it takes to store an anchor event.
func (nm NoOptMetrics) WriteAnchorStoreTime(value time.Duration) {}

// ProcessWitnessedAnchorCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (nm NoOptMetrics) ProcessWitnessedAnchorCredentialTime(value time.Duration) {}

// WriteAnchorSignCredentialTime records the time it takes to sign credential inside write anchor.
func (nm NoOptMetrics) WriteAnchorSignCredentialTime(value time.Duration) {}

// WriteAnchorPostOfferActivityTime records the time it takes to post offer activity inside write anchor.
func (nm NoOptMetrics) WriteAnchorPostOfferActivityTime(value time.Duration) {}

// WriteAnchorGetPreviousAnchorsGetBulkTime records the time it takes to get bulk inside previous anchor.
func (nm NoOptMetrics) WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration) {}

// WriteAnchorGetPreviousAnchorsTime records the time it takes to get previous anchor.
func (nm NoOptMetrics) WriteAnchorGetPreviousAnchorsTime(value time.Duration) {}

// WriteAnchorSignWithLocalWitnessTime records the time it takes to sign with local witness.
func (nm NoOptMetrics) WriteAnchorSignWithLocalWitnessTime(value time.Duration) {}

// WriteAnchorSignWithServerKeyTime records the time it takes to sign with server key.
func (nm NoOptMetrics) WriteAnchorSignWithServerKeyTime(value time.Duration) {}

// WriteAnchorSignLocalWitnessLogTime records the time it takes to witness log inside sign local.
func (nm NoOptMetrics) WriteAnchorSignLocalWitnessLogTime(value time.Duration) {}

// WriteAnchorSignLocalWatchTime records the time it takes to watch inside sign local.
func (nm NoOptMetrics) WriteAnchorSignLocalWatchTime(value time.Duration) {}

// WriteAnchorResolveHostMetaLinkTime records the time it takes to resolve host meta link.
func (nm NoOptMetrics) WriteAnchorResolveHostMetaLinkTime(value time.Duration) {}

// AddOperationTime records the time it takes to add an operation to the queue.
func (nm NoOptMetrics) AddOperationTime(value time.Duration) {}

// BatchCutTime records the time it takes to cut an operation batch. The duration is from the time
// that the first operation was added to the time that the batch is cut.
func (nm NoOptMetrics) BatchCutTime(value time.Duration) {}

// BatchRollbackTime records the time it takes to roll back an operation batch (in case of a
// transient error). The duration is from the time that the first operation was added to the time
// that the batch is cut.
func (nm NoOptMetrics) BatchRollbackTime(value time.Duration) {}

// BatchSize records the size of an operation batch.
func (nm NoOptMetrics) BatchSize(value float64) {}

// DecorateTime records the time it takes to decorate operation (for update handler).
func (nm NoOptMetrics) DecorateTime(duration time.Duration) {}

// ProcessorResolveTime records the time it takes for processor to resolve document
// when decorating operation (for update handler).
func (nm NoOptMetrics) ProcessorResolveTime(duration time.Duration) {}

// GetAOEndpointAndResolveDocumentFromAOTime records the time it takes to get anchor origin endpoint
// and resolve document from anchor origin when decorating operation (for update handler).
func (nm NoOptMetrics) GetAOEndpointAndResolveDocumentFromAOTime(duration time.Duration) {}

// ProcessOperation records the overall time to process operation.
func (nm NoOptMetrics) ProcessOperation(duration time.Duration) {}

// GetProtocolVersionTime records the time to get protocol version.
func (nm NoOptMetrics) GetProtocolVersionTime(since time.Duration) {}

// ParseOperationTime records the time to parse operation.
func (nm NoOptMetrics) ParseOperationTime(since time.Duration) {}

// ValidateOperationTime records the time to validate operation.
func (nm NoOptMetrics) ValidateOperationTime(since time.Duration) {}

// DecorateOperationTime records the time to decorate operation.
func (nm NoOptMetrics) DecorateOperationTime(since time.Duration) {}

// AddUnpublishedOperationTime records the time to add unpublished operation.
func (nm NoOptMetrics) AddUnpublishedOperationTime(since time.Duration) {}

// AddOperationToBatchTime records the time to add operation to batch.
func (nm NoOptMetrics) AddOperationToBatchTime(since time.Duration) {}

// GetCreateOperationResultTime records the time to create operation result response.
func (nm NoOptMetrics) GetCreateOperationResultTime(since time.Duration) {}

// SignCount increments the number of sign hits.
func (nm NoOptMetrics) SignCount() {}

// SignTime records the time for sign.
func (nm NoOptMetrics) SignTime(value time.Duration) {}

// ExportPublicKeyCount increments the number of export public key hits.
func (nm NoOptMetrics) ExportPublicKeyCount() {}

// ExportPublicKeyTime records the time for export public key.
func (nm NoOptMetrics) ExportPublicKeyTime(value time.Duration) {}

// VerifyCount increments the number of verify hits.
func (nm NoOptMetrics) VerifyCount() {}

// VerifyTime records the time for verify.
func (nm NoOptMetrics) VerifyTime(value time.Duration) {}

// DocumentResolveTime records the time it takes the REST handler to resolve a document.
func (nm NoOptMetrics) DocumentResolveTime(duration time.Duration) {}

// ResolveDocumentLocallyTime records resolving document locally.
func (nm NoOptMetrics) ResolveDocumentLocallyTime(duration time.Duration) {}

// GetAnchorOriginEndpointTime records getting anchor origin endpoint information.
func (nm NoOptMetrics) GetAnchorOriginEndpointTime(duration time.Duration) {}

// ResolveDocumentFromAnchorOriginTime records resolving document from anchor origin.
func (nm NoOptMetrics) ResolveDocumentFromAnchorOriginTime(duration time.Duration) {}

// DeleteDocumentFromCreateDocumentStoreTime records deleting document from create document store.
func (nm NoOptMetrics) DeleteDocumentFromCreateDocumentStoreTime(duration time.Duration) {}

// ResolveDocumentFromCreateDocumentStoreTime records resolving document from create document store.
func (nm NoOptMetrics) ResolveDocumentFromCreateDocumentStoreTime(duration time.Duration) {}

// VerifyCIDTime records verifying CID for document resolution.
func (nm NoOptMetrics) VerifyCIDTime(duration time.Duration) {}

// RequestDiscoveryTime records the time it takes to request discovery.
func (nm NoOptMetrics) RequestDiscoveryTime(duration time.Duration) {}

// DocumentCreateUpdateTime records the time it takes the REST handler to process a create/update operation.
func (nm NoOptMetrics) DocumentCreateUpdateTime(duration time.Duration) {}

// WebDocumentResolveTime records resolving web document.
func (nm NoOptMetrics) WebDocumentResolveTime(duration time.Duration) {}

// HTTPCreateUpdateTime records the time rest call for create or update.
func (nm NoOptMetrics) HTTPCreateUpdateTime(duration time.Duration) {}

// HTTPResolveTime records the time rest call for resolve.
func (nm NoOptMetrics) HTTPResolveTime(duration time.Duration) {}

// DBPutTime records the time it takes to store data in db.
func (nm NoOptMetrics) DBPutTime(dbType string, duration time.Duration) {}

// DBGetTime records the time it takes to get data in db.
func (nm NoOptMetrics) DBGetTime(dbType string, duration time.Duration) {}

// DBGetTagsTime records the time it takes to get tags in db.
func (nm NoOptMetrics) DBGetTagsTime(dbType string, duration time.Duration) {}

// DBGetBulkTime records the time it takes to get bulk in db.
func (nm NoOptMetrics) DBGetBulkTime(dbType string, duration time.Duration) {}

// DBQueryTime records the time it takes to query in db.
func (nm NoOptMetrics) DBQueryTime(dbType string, duration time.Duration) {}

// DBDeleteTime records the time it takes to delete in db.
func (nm NoOptMetrics) DBDeleteTime(dbType string, duration time.Duration) {}

// DBBatchTime records the time it takes to batch in db.
func (nm NoOptMetrics) DBBatchTime(dbType string, duration time.Duration) {}

// CASWriteSize the size (in bytes) of the data written to CAS for the given model type.
func (nm NoOptMetrics) CASWriteSize(dataType string, size int) {}
