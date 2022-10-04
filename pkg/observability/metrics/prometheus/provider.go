/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prometheus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/observability/metrics"
)

var logger = metrics.Logger

var (
	createOnce sync.Once       //nolint:gochecknoglobals
	instance   metrics.Metrics //nolint:gochecknoglobals
)

type promProvider struct {
	httpServer *httpserver.Server
}

// NewPrometheusProvider creates new instance of Prometheus Metrics Provider.
func NewPrometheusProvider(httpServer *httpserver.Server) metrics.Provider {
	return &promProvider{httpServer: httpServer}
}

// Create creates/initializes the prometheus metrics provider.
func (pp *promProvider) Create() error {
	if pp.httpServer != nil {
		return nil
	}

	if err := pp.httpServer.Start(); err != nil {
		return fmt.Errorf("start metrics HTTP server: %w", err)
	}

	return nil
}

// Metrics returns supported metrics.
func (pp *promProvider) Metrics() metrics.Metrics {
	return GetMetrics()
}

// Destroy destroys the prometheus metrics provider.
func (pp *promProvider) Destroy() error {
	if pp.httpServer != nil {
		return pp.httpServer.Stop(context.Background())
	}

	return nil
}

// GetMetrics returns metrics implementation.
func GetMetrics() metrics.Metrics {
	createOnce.Do(func() {
		instance = NewMetrics()
	})

	return instance
}

// PromMetrics manages the metrics for Orb.
type PromMetrics struct {
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
	anchorWriteStoreTime                     prometheus.Histogram
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

	webResolverResolveDocument prometheus.Histogram

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
	coreCASWriteSize                 map[string]prometheus.Gauge

	awsSignCount            prometheus.Counter
	awsSignTime             prometheus.Histogram
	awsExportPublicKeyCount prometheus.Counter
	awsExportPublicKeyTime  prometheus.Histogram
	awsVerifyCount          prometheus.Counter
	awsVerifyTime           prometheus.Histogram
}

// NewMetrics creates instance of prometheus metrics.
func NewMetrics() metrics.Metrics { //nolint:funlen
	activityTypes := []string{"Create", "Announce", "Offer", "Like", "Follow", "InviteWitness", "Accept", "Reject"}
	dbTypes := []string{"CouchDB", "MongoDB"}
	modelTypes := []string{"core index", "core proof", "provisional proof", "chunk", "provisional index"}

	pm := &PromMetrics{
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
		anchorWriteStoreTime:                         newAnchorWriteStoreTime(),
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
		webResolverResolveDocument:                   newWebResolverResolveDocument(),
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
		coreCASWriteSize:                             newCoreCASWriteSize(modelTypes),
		awsSignCount:                                 newAWSSignCount(),
		awsSignTime:                                  newAWSSignTime(),
		awsExportPublicKeyCount:                      newAWSExportPublicKeyCount(),
		awsExportPublicKeyTime:                       newAWSExportPublicKeyTime(),
		awsVerifyCount:                               newAWSVerifyCount(),
		awsVerifyTime:                                newAWSVerifyTime(),
	}

	registerMetrics(pm)

	return pm
}

func registerMetrics(pm *PromMetrics) { //nolint:funlen,gocyclo,cyclop
	prometheus.MustRegister(
		pm.apOutboxPostTime, pm.apOutboxResolveInboxesTime,
		pm.anchorWriteTime, pm.anchorWitnessTime, pm.anchorProcessWitnessedTime, pm.anchorWriteBuildCredTime,
		pm.anchorWriteGetWitnessesTime, pm.anchorWriteSignCredTime, pm.anchorWritePostOfferActivityTime,
		pm.anchorWriteGetPreviousAnchorsGetBulkTime, pm.anchorWriteGetPreviousAnchorsTime,
		pm.anchorWriteSignWithLocalWitnessTime, pm.anchorWriteSignWithServerKeyTime, pm.anchorWriteSignLocalWitnessLogTime,
		pm.anchorWriteStoreTime, pm.anchorWriteSignLocalWatchTime,
		pm.opqueueAddOperationTime, pm.opqueueBatchCutTime, pm.opqueueBatchRollbackTime,
		pm.opqueueBatchSize, pm.observerProcessAnchorTime, pm.observerProcessDIDTime,
		pm.casWriteTime, pm.casResolveTime, pm.casCacheHitCount,
		pm.docCreateUpdateTime, pm.docResolveTime,
		pm.vctWitnessAddProofVCTNilTimes, pm.vctWitnessAddVCTimes, pm.vctWitnessAddProofTimes,
		pm.vctWitnessAddWebFingerTimes, pm.vctWitnessVerifyVCTimes, pm.vctAddProofParseCredentialTimes,
		pm.vctAddProofSignTimes, pm.signerSignTimes, pm.signerGetKeyTimes, pm.signerAddLinkedDataProofTimes,
		pm.anchorWriteResolveHostMetaLinkTime,
		pm.webResolverResolveDocument,
		pm.resolverResolveDocumentLocallyTimes, pm.resolverGetAnchorOriginEndpointTimes,
		pm.resolverResolveDocumentFromAnchorOriginTimes,
		pm.resolverResolveDocumentFromCreateStoreTimes, pm.resolverDeleteDocumentFromCreateStoreTimes,
		pm.resolverVerifyCIDTimes, pm.resolverRequestDiscoveryTimes,
		pm.decoratorDecorateTime, pm.decoratorProcessorResolveTime, pm.decoratorGetAOEndpointAndResolveFromAOTime,
		pm.unpublishedPutOperationTime, pm.unpublishedGetOperationsTime, pm.unpublishedCalculateOperationKeyTime,
		pm.publishedPutOperationsTime, pm.publishedGetOperationsTime,
		pm.coreProcessOperationTime, pm.coreGetProtocolVersionTime,
		pm.coreParseOperationTime, pm.coreValidateOperationTime, pm.coreDecorateOperationTime,
		pm.coreAddUnpublishedOperationTime, pm.coreAddOperationToBatchTime, pm.coreGetCreateOperationResultTime,
		pm.coreHTTPCreateUpdateTime, pm.coreHTTPResolveTime, pm.awsSignCount, pm.awsSignTime,
		pm.awsExportPublicKeyCount,
		pm.awsExportPublicKeyTime, pm.awsVerifyTime, pm.awsVerifyCount,
	)

	for _, c := range pm.apInboxHandlerTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbPutTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbGetTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbGetTagsTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbGetBulkTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbBatchTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbDeleteTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.dbQueryTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.apOutboxActivityCounts {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.casReadTimes {
		prometheus.MustRegister(c)
	}

	for _, c := range pm.coreCASWriteSize {
		prometheus.MustRegister(c)
	}
}

// OutboxPostTime records the time it takes to post a message to the outbox.
func (pm *PromMetrics) OutboxPostTime(value time.Duration) {
	pm.apOutboxPostTime.Observe(value.Seconds())

	logger.Debug("OutboxPost time", log.WithDuration(value))
}

// OutboxResolveInboxesTime records the time it takes to resolve inboxes for an outbox post.
func (pm *PromMetrics) OutboxResolveInboxesTime(value time.Duration) {
	pm.apOutboxResolveInboxesTime.Observe(value.Seconds())

	logger.Debug("OutboxResolveInboxes time", log.WithDuration(value))
}

// InboxHandlerTime records the time it takes to handle an activity posted to the inbox.
func (pm *PromMetrics) InboxHandlerTime(activityType string, value time.Duration) {
	if c, ok := pm.apInboxHandlerTimes[activityType]; ok {
		c.Observe(value.Seconds())
	}

	logger.Debug("InboxHandler time for activity", log.WithActivityType(activityType), log.WithDuration(value))
}

// OutboxIncrementActivityCount increments the number of activities of the given type posted to the outbox.
func (pm *PromMetrics) OutboxIncrementActivityCount(activityType string) {
	if c, ok := pm.apOutboxActivityCounts[activityType]; ok {
		c.Inc()
	}
}

// WriteAnchorTime records the time it takes to write an anchor credential and post an 'Offer' activity.
func (pm *PromMetrics) WriteAnchorTime(value time.Duration) {
	pm.anchorWriteTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor time", log.WithDuration(value))
}

// WriteAnchorBuildCredentialTime records the time it takes to build credential inside write anchor.
func (pm *PromMetrics) WriteAnchorBuildCredentialTime(value time.Duration) {
	pm.anchorWriteBuildCredTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor build credential time", log.WithDuration(value))
}

// WriteAnchorGetWitnessesTime records the time it takes to get witnesses inside write anchor.
func (pm *PromMetrics) WriteAnchorGetWitnessesTime(value time.Duration) {
	pm.anchorWriteGetWitnessesTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor get witness time", log.WithDuration(value))
}

// WriteAnchorSignCredentialTime records the time it takes to sign credential inside write anchor.
func (pm *PromMetrics) WriteAnchorSignCredentialTime(value time.Duration) {
	pm.anchorWriteSignCredTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor sign credential time", log.WithDuration(value))
}

// WriteAnchorPostOfferActivityTime records the time it takes to post offer activity inside write anchor.
func (pm *PromMetrics) WriteAnchorPostOfferActivityTime(value time.Duration) {
	pm.anchorWritePostOfferActivityTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor sign credential time", log.WithDuration(value))
}

// WriteAnchorGetPreviousAnchorsGetBulkTime records the time it takes to get bulk inside previous anchor.
func (pm *PromMetrics) WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration) {
	pm.anchorWriteGetPreviousAnchorsGetBulkTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor getPreviousAnchor geBulk time", log.WithDuration(value))
}

// WriteAnchorGetPreviousAnchorsTime records the time it takes to get previous anchor.
func (pm *PromMetrics) WriteAnchorGetPreviousAnchorsTime(value time.Duration) {
	pm.anchorWriteGetPreviousAnchorsTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor getPreviousAnchor time", log.WithDuration(value))
}

// WriteAnchorSignWithLocalWitnessTime records the time it takes to sign with local witness.
func (pm *PromMetrics) WriteAnchorSignWithLocalWitnessTime(value time.Duration) {
	pm.anchorWriteSignWithLocalWitnessTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor sign with local witness time", log.WithDuration(value))
}

// WriteAnchorSignWithServerKeyTime records the time it takes to sign with server key.
func (pm *PromMetrics) WriteAnchorSignWithServerKeyTime(value time.Duration) {
	pm.anchorWriteSignWithServerKeyTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor sign with server key time", log.WithDuration(value))
}

// WriteAnchorSignLocalWitnessLogTime records the time it takes to witness log inside sign local.
func (pm *PromMetrics) WriteAnchorSignLocalWitnessLogTime(value time.Duration) {
	pm.anchorWriteSignLocalWitnessLogTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor witness log inside sign local time", log.WithDuration(value))
}

// WriteAnchorStoreTime records the time it takes to store an anchor event.
func (pm *PromMetrics) WriteAnchorStoreTime(value time.Duration) {
	pm.anchorWriteStoreTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor store time", log.WithDuration(value))
}

// WriteAnchorSignLocalWatchTime records the time it takes to watch inside sign local.
func (pm *PromMetrics) WriteAnchorSignLocalWatchTime(value time.Duration) {
	pm.anchorWriteSignLocalWatchTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor watch inside sign local time", log.WithDuration(value))
}

// WriteAnchorResolveHostMetaLinkTime records the time it takes to resolve host meta link.
func (pm *PromMetrics) WriteAnchorResolveHostMetaLinkTime(value time.Duration) {
	pm.anchorWriteResolveHostMetaLinkTime.Observe(value.Seconds())

	logger.Debug("WriteAnchor resolve host meta link time", log.WithDuration(value))
}

// WitnessAnchorCredentialTime records the time it takes for a verifiable credential to gather proofs from all
// required witnesses (according to witness policy). The start time is when the verifiable credential is issued
// and the end time is the time that the witness policy is satisfied.
func (pm *PromMetrics) WitnessAnchorCredentialTime(value time.Duration) {
	pm.anchorWitnessTime.Observe(value.Seconds())

	logger.Debug("WitnessAnchorCredential time", log.WithDuration(value))
}

// ProcessWitnessedAnchorCredentialTime records the time it takes to process a witnessed anchor credential
// by publishing it to the Observer and posting a 'Create' activity.
func (pm *PromMetrics) ProcessWitnessedAnchorCredentialTime(value time.Duration) {
	pm.anchorProcessWitnessedTime.Observe(value.Seconds())

	logger.Debug("ProcessWitnessedAnchorCredential time", log.WithDuration(value))
}

// AddOperationTime records the time it takes to add an operation to the queue.
func (pm *PromMetrics) AddOperationTime(value time.Duration) {
	pm.opqueueAddOperationTime.Observe(value.Seconds())

	logger.Debug("AddOperation time", log.WithDuration(value))
}

// BatchCutTime records the time it takes to cut an operation batch. The duration is from the time
// that the first operation was added to the time that the batch is cut.
func (pm *PromMetrics) BatchCutTime(value time.Duration) {
	pm.opqueueBatchCutTime.Observe(value.Seconds())

	logger.Info("BatchCut time", log.WithDuration(value))
}

// BatchRollbackTime records the time it takes to roll back an operation batch (in case of a
// transient error). The duration is from the time that the first operation was added to the time
// that the batch is cut.
func (pm *PromMetrics) BatchRollbackTime(value time.Duration) {
	pm.opqueueBatchRollbackTime.Observe(value.Seconds())

	logger.Debug("BatchRollback time", log.WithDuration(value))
}

// BatchSize records the size of an operation batch.
func (pm *PromMetrics) BatchSize(value float64) {
	pm.opqueueBatchSize.Set(value)

	logger.Info("BatchSize", log.WithSizeUint64(uint64(value)))
}

// ProcessAnchorTime records the time it takes for the Observer to process an anchor credential.
func (pm *PromMetrics) ProcessAnchorTime(value time.Duration) {
	pm.observerProcessAnchorTime.Observe(value.Seconds())

	logger.Info("ProcessAnchor time", log.WithDuration(value))
}

// ProcessDIDTime records the time it takes for the Observer to process a DID.
func (pm *PromMetrics) ProcessDIDTime(value time.Duration) {
	pm.observerProcessDIDTime.Observe(value.Seconds())

	logger.Debug("ProcessDID time", log.WithDuration(value))
}

// CASWriteTime records the time it takes to write a document to CAS.
func (pm *PromMetrics) CASWriteTime(value time.Duration) {
	pm.casWriteTime.Observe(value.Seconds())

	logger.Debug("CASWrite time", log.WithDuration(value))
}

// CASResolveTime records the time it takes to resolve a document from CAS.
func (pm *PromMetrics) CASResolveTime(value time.Duration) {
	pm.casResolveTime.Observe(value.Seconds())

	logger.Debug("CASResolve time", log.WithDuration(value))
}

// CASIncrementCacheHitCount increments the number of CAS cache hits.
func (pm *PromMetrics) CASIncrementCacheHitCount() {
	pm.casCacheHitCount.Inc()
}

// CASReadTime records the time it takes to read a document from CAS storage.
func (pm *PromMetrics) CASReadTime(casType string, value time.Duration) {
	if c, ok := pm.casReadTimes[casType]; ok {
		c.Observe(value.Seconds())
	}
}

// DocumentCreateUpdateTime records the time it takes the REST handler to process a create/update operation.
func (pm *PromMetrics) DocumentCreateUpdateTime(value time.Duration) {
	pm.docCreateUpdateTime.Observe(value.Seconds())

	logger.Debug("DocumentCreateUpdate time", log.WithDuration(value))
}

// DocumentResolveTime records the time it takes the REST handler to resolve a document.
func (pm *PromMetrics) DocumentResolveTime(value time.Duration) {
	pm.docResolveTime.Observe(value.Seconds())

	logger.Debug("DocumentResolve time", log.WithDuration(value))
}

// DBPutTime records the time it takes to store data in db.
func (pm *PromMetrics) DBPutTime(dbType string, value time.Duration) {
	if c, ok := pm.dbPutTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTime records the time it takes to get data in db.
func (pm *PromMetrics) DBGetTime(dbType string, value time.Duration) {
	if c, ok := pm.dbGetTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetTagsTime records the time it takes to get tags in db.
func (pm *PromMetrics) DBGetTagsTime(dbType string, value time.Duration) {
	if c, ok := pm.dbGetTagsTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBGetBulkTime records the time it takes to get bulk in db.
func (pm *PromMetrics) DBGetBulkTime(dbType string, value time.Duration) {
	if c, ok := pm.dbGetBulkTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBQueryTime records the time it takes to query in db.
func (pm *PromMetrics) DBQueryTime(dbType string, value time.Duration) {
	if c, ok := pm.dbQueryTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBDeleteTime records the time it takes to delete in db.
func (pm *PromMetrics) DBDeleteTime(dbType string, value time.Duration) {
	if c, ok := pm.dbDeleteTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// DBBatchTime records the time it takes to batch in db.
func (pm *PromMetrics) DBBatchTime(dbType string, value time.Duration) {
	if c, ok := pm.dbBatchTimes[dbType]; ok {
		c.Observe(value.Seconds())
	}
}

// WitnessAddProofVctNil records vct witness.
func (pm *PromMetrics) WitnessAddProofVctNil(value time.Duration) {
	pm.vctWitnessAddProofVCTNilTimes.Observe(value.Seconds())

	logger.Debug("vct witness add proof when vct nil time", log.WithDuration(value))
}

// WitnessAddVC records vct witness add vc.
func (pm *PromMetrics) WitnessAddVC(value time.Duration) {
	pm.vctWitnessAddVCTimes.Observe(value.Seconds())

	logger.Debug("vct witness add vc time", log.WithDuration(value))
}

// WitnessAddProof records vct witness add proof.
func (pm *PromMetrics) WitnessAddProof(value time.Duration) {
	pm.vctWitnessAddProofTimes.Observe(value.Seconds())

	logger.Debug("vct witness add vc proof", log.WithDuration(value))
}

// WitnessWebFinger records vct witness web finger.
func (pm *PromMetrics) WitnessWebFinger(value time.Duration) {
	pm.vctWitnessAddWebFingerTimes.Observe(value.Seconds())

	logger.Debug("vct witness web finger", log.WithDuration(value))
}

// WitnessVerifyVCTSignature records vct witness verify vct.
func (pm *PromMetrics) WitnessVerifyVCTSignature(value time.Duration) {
	pm.vctWitnessVerifyVCTimes.Observe(value.Seconds())

	logger.Debug("vct witness verify vct signature", log.WithDuration(value))
}

// AddProofParseCredential records vct parse credential in add proof.
func (pm *PromMetrics) AddProofParseCredential(value time.Duration) {
	pm.vctAddProofParseCredentialTimes.Observe(value.Seconds())

	logger.Debug("vct parse credential add proof", log.WithDuration(value))
}

// AddProofSign records vct sign in add proof.
func (pm *PromMetrics) AddProofSign(value time.Duration) {
	pm.vctAddProofSignTimes.Observe(value.Seconds())

	logger.Debug("vct sign add proof", log.WithDuration(value))
}

// SignerGetKey records get key time.
func (pm *PromMetrics) SignerGetKey(value time.Duration) {
	pm.signerGetKeyTimes.Observe(value.Seconds())

	logger.Debug("signer get key time", log.WithDuration(value))
}

// SignerAddLinkedDataProof records add data linked proof.
func (pm *PromMetrics) SignerAddLinkedDataProof(value time.Duration) {
	pm.signerAddLinkedDataProofTimes.Observe(value.Seconds())

	logger.Debug("signer add linked data proof time", log.WithDuration(value))
}

// WebDocumentResolveTime records resolving web document.
func (pm *PromMetrics) WebDocumentResolveTime(value time.Duration) {
	pm.webResolverResolveDocument.Observe(value.Seconds())

	logger.Debug("web resolver resolve document time", log.WithDuration(value))
}

// ResolveDocumentLocallyTime records resolving document locally.
func (pm *PromMetrics) ResolveDocumentLocallyTime(value time.Duration) {
	pm.resolverResolveDocumentLocallyTimes.Observe(value.Seconds())

	logger.Debug("resolver resolve document locally time", log.WithDuration(value))
}

// GetAnchorOriginEndpointTime records getting anchor origin endpoint information.
func (pm *PromMetrics) GetAnchorOriginEndpointTime(value time.Duration) {
	pm.resolverGetAnchorOriginEndpointTimes.Observe(value.Seconds())

	logger.Debug("resolver get anchor origin endpoint time", log.WithDuration(value))
}

// ResolveDocumentFromAnchorOriginTime records resolving document from anchor origin.
func (pm *PromMetrics) ResolveDocumentFromAnchorOriginTime(value time.Duration) {
	pm.resolverResolveDocumentFromAnchorOriginTimes.Observe(value.Seconds())

	logger.Debug("resolver resolve document from anchor origin time", log.WithDuration(value))
}

// DeleteDocumentFromCreateDocumentStoreTime records deleting document from create document store.
func (pm *PromMetrics) DeleteDocumentFromCreateDocumentStoreTime(value time.Duration) {
	pm.resolverDeleteDocumentFromCreateStoreTimes.Observe(value.Seconds())

	logger.Debug("resolver delete document from create store time", log.WithDuration(value))
}

// ResolveDocumentFromCreateDocumentStoreTime records resolving document from create document store.
func (pm *PromMetrics) ResolveDocumentFromCreateDocumentStoreTime(value time.Duration) {
	pm.resolverResolveDocumentFromCreateStoreTimes.Observe(value.Seconds())

	logger.Debug("resolver resolve document from create store time", log.WithDuration(value))
}

// VerifyCIDTime records verifying CID for document resolution.
func (pm *PromMetrics) VerifyCIDTime(value time.Duration) {
	pm.resolverVerifyCIDTimes.Observe(value.Seconds())

	logger.Debug("resolver verify CID time", log.WithDuration(value))
}

// RequestDiscoveryTime records the time it takes to request discovery.
func (pm *PromMetrics) RequestDiscoveryTime(value time.Duration) {
	pm.resolverRequestDiscoveryTimes.Observe(value.Seconds())

	logger.Debug("resolver request discovery time", log.WithDuration(value))
}

// DecorateTime records the time it takes to decorate operation (for update handler).
func (pm *PromMetrics) DecorateTime(value time.Duration) {
	pm.decoratorDecorateTime.Observe(value.Seconds())

	logger.Debug("decorator decorate time", log.WithDuration(value))
}

// ProcessorResolveTime records the time it takes for processor to resolve document
// when decorating operation (for update handler).
func (pm *PromMetrics) ProcessorResolveTime(value time.Duration) {
	pm.decoratorProcessorResolveTime.Observe(value.Seconds())

	logger.Debug("decorator processor resolve time", log.WithDuration(value))
}

// GetAOEndpointAndResolveDocumentFromAOTime records the time it takes to get anchor origin endpoint
// and resolve document from anchor origin when decorating operation (for update handler).
func (pm *PromMetrics) GetAOEndpointAndResolveDocumentFromAOTime(value time.Duration) {
	pm.decoratorGetAOEndpointAndResolveFromAOTime.Observe(value.Seconds())

	logger.Debug("decorator get anchor origin endpoint and resolve from anchor origin time",
		log.WithDuration(value))
}

// PutUnpublishedOperation records the time it takes to store unpublished operation.
func (pm *PromMetrics) PutUnpublishedOperation(value time.Duration) {
	pm.unpublishedPutOperationTime.Observe(value.Seconds())

	logger.Debug("unpublished put operation time", log.WithDuration(value))
}

// GetUnpublishedOperations records the time it takes to get unpublished operations for suffix.
func (pm *PromMetrics) GetUnpublishedOperations(value time.Duration) {
	pm.unpublishedGetOperationsTime.Observe(value.Seconds())

	logger.Debug("unpublished get operations for suffix time", log.WithDuration(value))
}

// CalculateUnpublishedOperationKey records the time to create unpublished operation key.
func (pm *PromMetrics) CalculateUnpublishedOperationKey(value time.Duration) {
	pm.unpublishedCalculateOperationKeyTime.Observe(value.Seconds())

	logger.Debug("unpublished calculate operation key time", log.WithDuration(value))
}

// PutPublishedOperations records the time to store published operations.
func (pm *PromMetrics) PutPublishedOperations(value time.Duration) {
	pm.publishedPutOperationsTime.Observe(value.Seconds())

	logger.Debug("published put operations time", log.WithDuration(value))
}

// GetPublishedOperations records the time to get published operations for suffix.
func (pm *PromMetrics) GetPublishedOperations(value time.Duration) {
	pm.publishedGetOperationsTime.Observe(value.Seconds())

	logger.Debug("published get operations for suffix time", log.WithDuration(value))
}

// ProcessOperation records the overall time to process operation.
func (pm *PromMetrics) ProcessOperation(value time.Duration) {
	pm.coreProcessOperationTime.Observe(value.Seconds())

	logger.Debug("core process operation time", log.WithDuration(value))
}

// GetProtocolVersionTime records the time to get protocol version.
func (pm *PromMetrics) GetProtocolVersionTime(value time.Duration) {
	pm.coreGetProtocolVersionTime.Observe(value.Seconds())

	logger.Debug("core get protocol version(process operation)", log.WithDuration(value))
}

// ParseOperationTime records the time to parse operation.
func (pm *PromMetrics) ParseOperationTime(value time.Duration) {
	pm.coreParseOperationTime.Observe(value.Seconds())

	logger.Debug("core parse operation(process operation)", log.WithDuration(value))
}

// ValidateOperationTime records the time to validate operation.
func (pm *PromMetrics) ValidateOperationTime(value time.Duration) {
	pm.coreValidateOperationTime.Observe(value.Seconds())

	logger.Debug("core validate operation(process operation)", log.WithDuration(value))
}

// DecorateOperationTime records the time to decorate operation.
func (pm *PromMetrics) DecorateOperationTime(value time.Duration) {
	pm.coreDecorateOperationTime.Observe(value.Seconds())

	logger.Debug("core decorate operation(process operation)", log.WithDuration(value))
}

// AddUnpublishedOperationTime records the time to add unpublished operation.
func (pm *PromMetrics) AddUnpublishedOperationTime(value time.Duration) {
	pm.coreAddUnpublishedOperationTime.Observe(value.Seconds())

	logger.Debug("core add unpublished operation(process operation)", log.WithDuration(value))
}

// AddOperationToBatchTime records the time to add operation to batch.
func (pm *PromMetrics) AddOperationToBatchTime(value time.Duration) {
	pm.coreAddOperationToBatchTime.Observe(value.Seconds())

	logger.Debug("core add operation to batch(process operation)", log.WithDuration(value))
}

// GetCreateOperationResultTime records the time to create operation result response.
func (pm *PromMetrics) GetCreateOperationResultTime(value time.Duration) {
	pm.coreGetCreateOperationResultTime.Observe(value.Seconds())

	logger.Debug("core get create operation result(process operation)", log.WithDuration(value))
}

// HTTPCreateUpdateTime records the time rest call for create or update.
func (pm *PromMetrics) HTTPCreateUpdateTime(value time.Duration) {
	pm.coreHTTPCreateUpdateTime.Observe(value.Seconds())

	logger.Debug("core http create update", log.WithDuration(value))
}

// HTTPResolveTime records the time rest call for resolve.
func (pm *PromMetrics) HTTPResolveTime(value time.Duration) {
	pm.coreHTTPResolveTime.Observe(value.Seconds())

	logger.Debug("core http resolve", log.WithDuration(value))
}

// CASWriteSize the size (in bytes) of the data written to CAS for the given model type.
func (pm *PromMetrics) CASWriteSize(modelType string, size int) {
	if c, ok := pm.coreCASWriteSize[modelType]; ok {
		c.Set(float64(size))
	} else {
		logger.Warn("Metric for CAS model type not registered. Reason: Unsupported model type.",
			log.WithType(modelType))
	}

	logger.Debug("CAS write size for model type", log.WithType(modelType), log.WithSize(size))
}

// SignerSign records sign.
func (pm *PromMetrics) SignerSign(value time.Duration) {
	pm.signerSignTimes.Observe(value.Seconds())

	logger.Debug("signer sign time", log.WithDuration(value))
}

// SignCount increments the number of sign hits.
func (pm *PromMetrics) SignCount() {
	pm.awsSignCount.Inc()
}

// SignTime records the time for sign.
func (pm *PromMetrics) SignTime(value time.Duration) {
	pm.awsSignTime.Observe(value.Seconds())

	logger.Debug("aws sign time", log.WithDuration(value))
}

// ExportPublicKeyCount increments the number of export public key hits.
func (pm *PromMetrics) ExportPublicKeyCount() {
	pm.awsExportPublicKeyCount.Inc()
}

// ExportPublicKeyTime records the time for export public key.
func (pm *PromMetrics) ExportPublicKeyTime(value time.Duration) {
	pm.awsExportPublicKeyTime.Observe(value.Seconds())

	logger.Debug("aws export public key time", log.WithDuration(value))
}

// VerifyCount increments the number of verify hits.
func (pm *PromMetrics) VerifyCount() {
	pm.awsVerifyCount.Inc()
}

// VerifyTime records the time for verify.
func (pm *PromMetrics) VerifyTime(value time.Duration) {
	pm.awsVerifyTime.Observe(value.Seconds())

	logger.Debug("aws verify time", log.WithDuration(value))
}

func newCounter(subsystem, name, help string, labels prometheus.Labels) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newGauge(subsystem, name, help string, labels prometheus.Labels) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newHistogram(subsystem, name, help string, labels prometheus.Labels) prometheus.Histogram {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystem,
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	})
}

func newOutboxPostTime() prometheus.Histogram {
	return newHistogram(
		metrics.ActivityPub, metrics.ApPostTimeMetric,
		"The time (in seconds) that it takes to post a message to the outbox.",
		nil,
	)
}

func newOutboxResolveInboxesTime() prometheus.Histogram {
	return newHistogram(
		metrics.ActivityPub, metrics.ApResolveInboxesTimeMetric,
		"The time (in seconds) that it takes to resolve the inboxes of the destinations when posting to the outbox.",
		nil,
	)
}

func newInboxHandlerTimes(activityTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, activityType := range activityTypes {
		counters[activityType] = newHistogram(
			metrics.ActivityPub, metrics.ApInboxHandlerTimeMetric,
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
			metrics.ActivityPub, metrics.ApOutboxActivityCounterMetric,
			"The number of activities posted to the outbox.",
			prometheus.Labels{"type": activityType},
		)
	}

	return counters
}

func newAnchorWriteTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteTimeMetric,
		"The time (in seconds) that it takes to write an anchor credential and post an 'Offer' activity.",
		nil,
	)
}

func newAnchorWitnessTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWitnessMetric,
		"The time (in seconds) that it takes for a verifiable credential to gather proofs from all required "+
			"witnesses (according to witness policy). The start time is when the verifiable credential is issued "+
			"and the end time is the time that the witness policy is satisfied.",
		nil,
	)
}

func newAnchorProcessWitnessedTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorProcessWitnessedMetric,
		"The time (in seconds) that it takes to process a witnessed anchor credential by publishing it to "+
			"the Observer and posting a 'Create' activity.",
		nil,
	)
}

func newAnchorWriteBuildCredTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteBuildCredTimeMetric,
		"The time (in seconds) that it takes to build credential inside write anchor.",
		nil,
	)
}

func newAnchorWriteGetWitnessesTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteGetWitnessesTimeMetric,
		"The time (in seconds) that it takes to get witnesses inside write anchor.",
		nil,
	)
}

func newAnchorWriteSignCredTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteSignCredTimeMetric,
		"The time (in seconds) that it takes to sign credential inside write anchor.",
		nil,
	)
}

func newAnchorWritePostOfferActivityTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWritePostOfferActivityTimeMetric,
		"The time (in seconds) that it takes to post offer activity inside write anchor.",
		nil,
	)
}

func newAnchorWriteGetPreviousAnchorsGetBulkTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteGetPreviousAnchorsGetBulkTimeMetric,
		"The time (in seconds) that it takes to get bulk inside get previous anchor.",
		nil,
	)
}

func newAnchorWriteGetPreviousAnchorsTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteGetPreviousAnchorsTimeMetric,
		"The time (in seconds) that it takes to get previous anchor.",
		nil,
	)
}

func newAnchorWriteSignWithLocalWitnessTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteSignWithLocalWitnessTimeMetric,
		"The time (in seconds) that it takes to sign with local witness.",
		nil,
	)
}

func newAnchorWriteSignWithServerKeyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteSignWithServerKeyTimeMetric,
		"The time (in seconds) that it takes to sign with server key.",
		nil,
	)
}

func newAnchorWriteSignLocalWitnessLogTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteSignLocalWitnessLogTimeMetric,
		"The time (in seconds) that it takes to witness log inside sign local.",
		nil,
	)
}

func newAnchorWriteStoreTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteStoreTimeMetric,
		"The time (in seconds) that it takes to store an anchor event.",
		nil,
	)
}

func newAnchorWriteSignLocalWatchTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteSignLocalWatchTimeMetric,
		"The time (in seconds) that it takes to watxch inside sign local.",
		nil,
	)
}

func newAnchorWriteResolveHostMetaLinkTime() prometheus.Histogram {
	return newHistogram(
		metrics.Anchor, metrics.AnchorWriteResolveHostMetaLinkTimeMetric,
		"The time (in seconds) that it takes to resolve host meta link.",
		nil,
	)
}

func newOpQueueAddOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.OperationQueue, metrics.OpQueueAddOperationTimeMetric,
		"The time (in seconds) that it takes to add an operation to the queue.",
		nil,
	)
}

func newOpQueueBatchCutTime() prometheus.Histogram {
	return newHistogram(
		metrics.OperationQueue, metrics.OpQueueBatchCutTimeMetric,
		"The time (in seconds) that it takes to cut an operation batch. The duration is from the time that the first "+
			"operation was added to the time that the batch was cut.",
		nil,
	)
}

func newOpQueueBatchRollbackTime() prometheus.Histogram {
	return newHistogram(
		metrics.OperationQueue, metrics.OpQueueBatchRollbackTimeMetric,
		"The time (in seconds) that it takes to roll back an operation batch (in case of a transient error). "+
			"The duration is from the time that the first operation was added to the time that the batch was cut.",
		nil,
	)
}

func newOpQueueBatchSize() prometheus.Gauge {
	return newGauge(
		metrics.OperationQueue, metrics.OpQueueBatchSizeMetric,
		"The size of a cut batch.",
		nil,
	)
}

func newObserverProcessAnchorTime() prometheus.Histogram {
	return newHistogram(
		metrics.Observer, metrics.ObserverProcessAnchorTimeMetric,
		"The time (in seconds) that it takes for the Observer to process an anchor credential.",
		nil,
	)
}

func newObserverProcessDIDTime() prometheus.Histogram {
	return newHistogram(
		metrics.Observer, metrics.ObserverProcessDIDTimeMetric,
		"The time (in seconds) that it takes for the Observer to process a DID.",
		nil,
	)
}

func newCASWriteTime() prometheus.Histogram {
	return newHistogram(
		metrics.Cas, metrics.CasWriteTimeMetric,
		"The time (in seconds) that it takes to write a document to CAS.",
		nil,
	)
}

func newCASResolveTime() prometheus.Histogram {
	return newHistogram(
		metrics.Cas, metrics.CasResolveTimeMetric,
		"The time (in seconds) that it takes to resolve a document from CAS.",
		nil,
	)
}

func newCASCacheHitCount() prometheus.Counter {
	return newCounter(
		metrics.Cas, metrics.CasCacheHitCountMetric,
		"The number of times a CAS document was retrieved from the cache.",
		nil,
	)
}

func newCASReadTimes() map[string]prometheus.Histogram {
	times := make(map[string]prometheus.Histogram)

	for _, casType := range []string{"local", "ipfs"} {
		times[casType] = newHistogram(
			metrics.Cas, metrics.CasReadTimeMetric,
			"The time (in seconds) that it takes to read a document from the CAS storage.",
			prometheus.Labels{"type": casType},
		)
	}

	return times
}

func newDocCreateUpdateTime() prometheus.Histogram {
	return newHistogram(
		metrics.Document, metrics.DocCreateUpdateTimeMetric,
		"The time (in seconds) it takes the REST handler to process a create/update operation.",
		nil,
	)
}

func newDocResolveTime() prometheus.Histogram {
	return newHistogram(
		metrics.Document, metrics.DocResolveTimeMetric,
		"The time (in seconds) it takes the REST handler to resolve a document.",
		nil,
	)
}

func newDBPutTime(dbTypes []string) map[string]prometheus.Histogram {
	counters := make(map[string]prometheus.Histogram)

	for _, dbType := range dbTypes {
		counters[dbType] = newHistogram(
			metrics.DB, metrics.DBPutTimeMetric,
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
			metrics.DB, metrics.DBGetTimeMetric,
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
			metrics.DB, metrics.DBGetTagsTimeMetric,
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
			metrics.DB, metrics.DBGetBulkTimeMetric,
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
			metrics.DB, metrics.DBQueryTimeMetric,
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
			metrics.DB, metrics.DBDeleteTimeMetric,
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
			metrics.DB, metrics.DBBatchTimeMetric,
			"The time (in seconds) it takes the DB to batch.",
			prometheus.Labels{"type": dbType},
		)
	}

	return counters
}

func newVCTWitnessAddProofVCTNilTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctWitnessAddProofVCTNilTimeMetric,
		"The time (in seconds) it takes the add proof when vct is nil in witness.",
		nil,
	)
}

func newVCTWitnessAddVCTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctWitnessAddVCTimeMetric,
		"The time (in seconds) it takes the add vc in witness.",
		nil,
	)
}

func newVCTWitnessAddProofTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctWitnessAddProofTimeMetric,
		"The time (in seconds) it takes the add proof in witness.",
		nil,
	)
}

func newVCTWitnessWebFingerTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctWitnessWebFingerTimeMetric,
		"The time (in seconds) it takes web finger in witness.",
		nil,
	)
}

func newVCTWitnessVerifyVCTTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctWitnessVerifyVCTTimeMetric,
		"The time (in seconds) it takes verify vct signature in witness.",
		nil,
	)
}

func newVCTAddProofParseCredentialTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctAddProofParseCredentialTimeMetric,
		"The time (in seconds) it takes the parse credential in add proof.",
		nil,
	)
}

func newVCTAddProofSignTime() prometheus.Histogram {
	return newHistogram(
		metrics.Vct, metrics.VctAddProofSignTimeMetric,
		"The time (in seconds) it takes the sign in add proof.",
		nil,
	)
}

func newSignerGetKeyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Signer, metrics.SignerGetKeyTimeMetric,
		"The time (in seconds) it takes the signer to get key.",
		nil,
	)
}

func newSignerSignTime() prometheus.Histogram {
	return newHistogram(
		metrics.Signer, metrics.SignerSignMetric,
		"The time (in seconds) it takes the signer to sign.",
		nil,
	)
}

func newSignerAddLinkedDataProofTime() prometheus.Histogram {
	return newHistogram(
		metrics.Signer, metrics.SignerAddLinkedDataProofMetric,
		"The time (in seconds) it takes the signer to add data linked prrof.",
		nil,
	)
}

func newWebResolverResolveDocument() prometheus.Histogram {
	return newHistogram(
		metrics.WebResolver, metrics.WebResolverResolveDocument,
		"The time (in seconds) it takes the web resolver to resolve document.",
		nil,
	)
}

func newResolverResolveDocumentLocallyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverResolveDocumentLocallyTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document locally.",
		nil,
	)
}

func newResolverGetAnchorOriginEndpointTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverGetAnchorOriginEndpointTimeMetric,
		"The time (in seconds) it takes the resolver to get endpoint information from anchor origin.",
		nil,
	)
}

func newResolverResolveDocumentFromAnchorOriginTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverResolveDocumentFromAnchorOriginTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document from anchor origin.",
		nil,
	)
}

func newResolverResolveDocumentFromCreateStoreTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverResolveDocumentFromCreateStoreTimeMetric,
		"The time (in seconds) it takes the resolver to resolve document from create document store.",
		nil,
	)
}

func newResolverDeleteDocumentFromCreateStoreTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverDeleteDocumentFromCreateStoreTimeMetric,
		"The time (in seconds) it takes the resolver to delete document from create document store.",
		nil,
	)
}

func newResolverVerifyCIDTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverVerifyCIDTimeMetric,
		"The time (in seconds) it takes the resolver to verify CID in anchor graph.",
		nil,
	)
}

func newResolverRequestDiscoveryTime() prometheus.Histogram {
	return newHistogram(
		metrics.Resolver, metrics.ResolverRequestDiscoveryTimeMetric,
		"The time (in seconds) it takes the resolver to request DID discovery.",
		nil,
	)
}

func newDecoratorDecorateTime() prometheus.Histogram {
	return newHistogram(
		metrics.Decorator, metrics.DecoratorDecorateTimeMetric,
		"The time (in seconds) it takes the decorator to pre-process document operation.",
		nil,
	)
}

func newDecoratorProcessorResolveTime() prometheus.Histogram {
	return newHistogram(
		metrics.Decorator, metrics.DecoratorProcessorResolveTimeMetric,
		"The time (in seconds) it takes the processor to resolve document before accepting document operation.",
		nil,
	)
}

func newDecoratorGetAOEndpointAndResolveFromAOTime() prometheus.Histogram {
	return newHistogram(
		metrics.Decorator, metrics.DecoratorGetAOEndpointAndResolveFromAOTimeMetric,
		"The time (in seconds) it takes to resolve document from anchor origin before accepting document operation.",
		nil,
	)
}

func newUnpublishedPutOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.Operations, metrics.UnpublishedPutOperationTimeMetric,
		"The time (in seconds) it takes to store unpublished operation.",
		nil,
	)
}

func newUnpublishedGetOperationsTime() prometheus.Histogram {
	return newHistogram(
		metrics.Operations, metrics.UnpublishedGetOperationsTimeMetric,
		"The time (in seconds) it takes to get unpublished operations for suffix.",
		nil,
	)
}

func newUnpublishedCalculateKeyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Operations, metrics.UnpublishedCalculateOperationKeyTimeMetric,
		"The time (in seconds) it takes to calculate key for unpublished operation.",
		nil,
	)
}

func newPublishedPutOperationsTime() prometheus.Histogram {
	return newHistogram(
		metrics.Operations, metrics.PublishedPutOperationsTimeMetric,
		"The time (in seconds) it takes to store published operations.",
		nil,
	)
}

func newPublishedGetOperationsTime() prometheus.Histogram {
	return newHistogram(
		metrics.Operations, metrics.PublishedGetOperationsTimeMetric,
		"The time (in seconds) it takes to get published operations for suffix.",
		nil,
	)
}

func newCoreProcessOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreProcessOperationTimeMetrics,
		"The time (in seconds) it takes to process did operation(core).",
		nil,
	)
}

func newCoreGetProtocolVersionTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreGetProtocolVersionTimeMetrics,
		"The time (in seconds) it takes to get protocol version in process operation(core).",
		nil,
	)
}

func newCoreParseOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreParseOperationTimeMetrics,
		"The time (in seconds) it takes to parse operation in process operation(core).",
		nil,
	)
}

func newCoreValidateOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreValidateOperationTimeMetrics,
		"The time (in seconds) it takes to validate operation in process operation(core).",
		nil,
	)
}

func newCoreDecorateOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreDecorateOperationTimeMetrics,
		"The time (in seconds) it takes to decorate operation in process operation(core).",
		nil,
	)
}

func newCoreAddUnpublishedOperationTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreAddUnpublishedOperationTimeMatrix,
		"The time (in seconds) it takes to add unpublished operation to store in process operation(core).",
		nil,
	)
}

func newCoreAddOperationToBatchTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreAddOperationToBatchTimeMatrix,
		"The time (in seconds) it takes to add operation to batch in process operation(core).",
		nil,
	)
}

func newCoreGetCreateOperationResultTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreGetCreateOperationResult,
		"The time (in seconds) it takes to get create operation result in process operation(core).",
		nil,
	)
}

func newCoreHTTPCreateUpdateTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreHTTPCreateUpdateTimeMetrics,
		"The time (in seconds) it takes for create update http call.",
		nil,
	)
}

func newCoreHTTPResolveTime() prometheus.Histogram {
	return newHistogram(
		metrics.CoreOperations, metrics.CoreHTTPResolveTimeMetrics,
		"The time (in seconds) it takes for resolve http call.",
		nil,
	)
}

func newCoreCASWriteSize(modelTypes []string) map[string]prometheus.Gauge {
	gauges := make(map[string]prometheus.Gauge)

	for _, modelType := range modelTypes {
		gauges[modelType] = newGauge(
			metrics.CoreOperations, metrics.CoreCASWriteSizeMetrics,
			"The size (in bytes) of written CAS data.",
			prometheus.Labels{"type": modelType},
		)
	}

	return gauges
}

func newAWSSignCount() prometheus.Counter {
	return newCounter(
		metrics.Aws, metrics.AwsSignCountMetric,
		"The number of times sign called.",
		nil,
	)
}

func newAWSSignTime() prometheus.Histogram {
	return newHistogram(
		metrics.Aws, metrics.AwsSignTimeMetric,
		"The time (in seconds) it takes for sign.",
		nil,
	)
}

func newAWSExportPublicKeyCount() prometheus.Counter {
	return newCounter(
		metrics.Aws, metrics.AwsExportPublicKeyCountMetric,
		"The number of times export public key called.",
		nil,
	)
}

func newAWSExportPublicKeyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Aws, metrics.AwsExportPublicKeyTimeMetric,
		"The time (in seconds) it takes for export public key.",
		nil,
	)
}

func newAWSVerifyCount() prometheus.Counter {
	return newCounter(
		metrics.Aws, metrics.AwsVerifyCountMetric,
		"The number of times verify called.",
		nil,
	)
}

func newAWSVerifyTime() prometheus.Histogram {
	return newHistogram(
		metrics.Aws, metrics.AwsVerifyTimeMetric,
		"The time (in seconds) it takes for verify.",
		nil,
	)
}
