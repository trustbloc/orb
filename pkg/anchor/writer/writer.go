/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/hashlink"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

var logger = log.New("anchor-writer")

type metricsProvider interface {
	WriteAnchorTime(value time.Duration)
	WriteAnchorBuildCredentialTime(value time.Duration)
	WriteAnchorGetWitnessesTime(value time.Duration)
	WriteAnchorStoreTime(value time.Duration)
	ProcessWitnessedAnchorCredentialTime(value time.Duration)
	WriteAnchorSignCredentialTime(value time.Duration)
	WriteAnchorPostOfferActivityTime(value time.Duration)
	WriteAnchorGetPreviousAnchorsGetBulkTime(value time.Duration)
	WriteAnchorGetPreviousAnchorsTime(value time.Duration)
	WriteAnchorSignWithLocalWitnessTime(value time.Duration)
	WriteAnchorSignWithServerKeyTime(value time.Duration)
	WriteAnchorSignLocalWitnessLogTime(value time.Duration)
	WriteAnchorSignLocalWatchTime(value time.Duration)
	WriteAnchorResolveHostMetaLinkTime(value time.Duration)
}

type proofHandler interface {
	HandleProof(witness *url.URL, anchorID string, endTime time.Time, proof []byte) error
}

// Writer implements writing anchors.
type Writer struct {
	*Providers
	namespace            string
	anchorPublisher      anchorPublisher
	apServiceIRI         *url.URL
	casIRI               *url.URL
	maxWitnessDelay      time.Duration
	signWithLocalWitness bool
	resourceResolver     *resourceresolver.Resolver
	metrics              metricsProvider
}

// Providers contains all of the providers required by the client.
type Providers struct {
	AnchorGraph            anchorGraph
	DidAnchors             didAnchors
	AnchorBuilder          anchorBuilder
	AnchorEventStore       anchorEventStore
	AnchorEventStatusStore statusStore
	OpProcessor            opProcessor
	Outbox                 outbox
	ProofHandler           proofHandler
	Witness                witness
	Signer                 signer
	MonitoringSvc          monitoringSvc
	WitnessStore           witnessStore
	WitnessPolicy          witnessPolicy
	ActivityStore          activityStore
	WFClient               webfingerClient
	DocumentLoader         ld.DocumentLoader
	VCStore                storage.Store
}

type webfingerClient interface {
	HasSupportedLedgerType(domain string) (bool, error)
}

type activityStore interface {
	QueryReferences(refType spi.ReferenceType, query *spi.Criteria, opts ...spi.QueryOpt) (spi.ReferenceIterator, error)
}

type witnessStore interface {
	Put(anchorEventID string, witnesses []*proof.Witness) error
	Delete(anchorEventID string) error
}

type witnessPolicy interface {
	Select(witnesses []*proof.Witness, exclude ...*proof.Witness) ([]*proof.Witness, error)
}

type witness interface {
	Witness(anchorCred []byte) ([]byte, error)
}

type signer interface {
	Sign(vc *verifiable.Credential, opts ...vcsigner.Opt) (*verifiable.Credential, error)
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type outbox interface {
	Post(activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

type opProcessor interface {
	Resolve(uniqueSuffix string, additionalOps ...*operation.AnchoredOperation) (*protocol.ResolutionModel, error)
}

type anchorGraph interface {
	Add(anchorEvent *vocab.AnchorEventType) (string, error)
}

type anchorBuilder interface {
	Build(anchorHashlink string) (*verifiable.Credential, error)
}

type didAnchors interface {
	GetBulk(did []string) ([]string, error)
}

type anchorEventStore interface {
	Put(anchorEvent *vocab.AnchorEventType) error
	Delete(id string) error
}

type statusStore interface {
	AddStatus(vcID string, status proof.AnchorIndexStatus) error
}

type anchorPublisher interface {
	PublishAnchor(anchorInfo *anchorinfo.AnchorInfo) error
}

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
}

// New returns a new anchor writer.
func New(namespace string, apServiceIRI, casURL *url.URL, providers *Providers,
	anchorPublisher anchorPublisher, pubSub pubSub,
	maxWitnessDelay time.Duration, signWithLocalWitness bool,
	resourceResolver *resourceresolver.Resolver,
	metrics metricsProvider) (*Writer, error) {
	w := &Writer{
		Providers:            providers,
		anchorPublisher:      anchorPublisher,
		namespace:            namespace,
		apServiceIRI:         apServiceIRI,
		casIRI:               casURL,
		maxWitnessDelay:      maxWitnessDelay,
		signWithLocalWitness: signWithLocalWitness,
		resourceResolver:     resourceResolver,
		metrics:              metrics,
	}

	s, err := vcpubsub.NewSubscriber(pubSub, w.handle)
	if err != nil {
		return nil, fmt.Errorf("new subscriber: %w", err)
	}

	s.Start()

	return w, nil
}

// WriteAnchor writes Sidetree anchor string to Orb anchor.
func (c *Writer) WriteAnchor(anchor string, attachments []*protocol.AnchorDocument,
	refs []*operation.Reference, version uint64) error {
	startTime := time.Now()

	defer func() { c.metrics.WriteAnchorTime(time.Since(startTime)) }()

	// get previous anchors for each did that is referenced in this anchor
	previousAnchors, err := c.getPreviousAnchors(refs)
	if err != nil {
		return fmt.Errorf("get previous anchors: %w", err)
	}

	ad, err := util.ParseAnchorString(anchor)
	if err != nil {
		return fmt.Errorf("parse anchor string [%s]: %w", anchor, err)
	}

	now := time.Now()

	payload := &subject.Payload{
		OperationCount:  ad.OperationCount,
		CoreIndex:       ad.CoreIndexFileURI,
		Namespace:       c.namespace,
		Version:         version,
		PreviousAnchors: previousAnchors,
		Attachments:     getAttachmentURIs(attachments),
		AnchorOrigin:    c.apServiceIRI.String(),
		Published:       &now,
	}

	// figure out witness list for this anchor file
	batchWitnesses, err := c.getWitnessesFromBatchOperations(refs)
	if err != nil {
		return fmt.Errorf("failed to create witness list: %w", err)
	}

	anchorEvent, vc, err := c.buildAnchorEvent(payload, batchWitnesses)
	if err != nil {
		return fmt.Errorf("build anchor event for anchor [%s]: %w", anchor, err)
	}

	storeStartTime := time.Now()

	err = c.AnchorEventStore.Put(anchorEvent)
	if err != nil {
		return fmt.Errorf("store anchor event: %w", err)
	}

	c.metrics.WriteAnchorStoreTime(time.Since(storeStartTime))

	logger.Debugf("signed and stored anchor event %s for anchor: %s", anchorEvent.Index(), anchor)

	// send an offer activity to witnesses (request witnessing anchor credential from non-local witness logs)
	err = c.postOfferActivity(anchorEvent, vc, batchWitnesses)
	if err != nil {
		return fmt.Errorf("failed to post new offer activity for anchor event %s: %w",
			anchorEvent.Index(), err)
	}

	return nil
}

func (c *Writer) buildAnchorEvent(payload *subject.Payload,
	witnesses []string) (*vocab.AnchorEventType, vocab.Document, error) {
	indexContentObj, err := anchorevent.BuildContentObject(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("build content object: %w", err)
	}

	vc, err := c.buildCredential(indexContentObj.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("build credential: %w", err)
	}

	// sign credential using local witness log or server public key
	vc, err = c.signCredential(vc, witnesses)
	if err != nil {
		return nil, nil, fmt.Errorf("sign credential: %w", err)
	}

	witnessContentObj, err := vocab.MarshalToDoc(vc)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal verifiable credential to doc: %w", err)
	}

	anchorEvent, err := anchorevent.BuildAnchorEvent(payload, indexContentObj.GeneratorID,
		indexContentObj.Payload, witnessContentObj)
	if err != nil {
		return nil, nil, fmt.Errorf("build anchor event: %w", err)
	}

	return anchorEvent, witnessContentObj, nil
}

func (c *Writer) getPreviousAnchors(refs []*operation.Reference) ([]*subject.SuffixAnchor, error) {
	getPreviousAnchorsStartTime := time.Now()

	defer c.metrics.WriteAnchorGetPreviousAnchorsTime(time.Since(getPreviousAnchorsStartTime))

	// assemble map of latest did anchor references
	var previousAnchors []*subject.SuffixAnchor

	suffixes := getSuffixes(refs)

	getBulkStartTime := time.Now()

	anchors, err := c.DidAnchors.GetBulk(suffixes)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve latest did anchor references for suffixes[%s]", suffixes)
	}

	c.metrics.WriteAnchorGetPreviousAnchorsGetBulkTime(time.Since(getBulkStartTime))

	for i, ref := range refs {
		if anchors[i] == "" {
			if ref.Type != operation.TypeCreate {
				return nil, fmt.Errorf("previous did anchor reference not found for %s operation for did[%s]", ref.Type, ref.UniqueSuffix) //nolint:lll
			}

			// create doesn't have previous anchor references
			previousAnchors = append(previousAnchors, &subject.SuffixAnchor{Suffix: ref.UniqueSuffix})
		} else {
			previousAnchors = append(previousAnchors, &subject.SuffixAnchor{Suffix: ref.UniqueSuffix, Anchor: anchors[i]})
		}
	}

	return previousAnchors, nil
}

func getSuffixes(refs []*operation.Reference) []string {
	suffixes := make([]string, len(refs))
	for i, ref := range refs {
		suffixes[i] = ref.UniqueSuffix
	}

	return suffixes
}

// buildCredential builds and signs anchor credential.
func (c *Writer) buildCredential(contentObj vocab.Document) (*verifiable.Credential, error) {
	buildCredStartTime := time.Now()

	defer c.metrics.WriteAnchorBuildCredentialTime(time.Since(buildCredStartTime))

	contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
	if err != nil {
		return nil, fmt.Errorf("marshal content object: %w", err)
	}

	hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("create hashlink for content object: %w", err)
	}

	vc, err := c.AnchorBuilder.Build(hl)
	if err != nil {
		return nil, fmt.Errorf("build anchor credential: %w", err)
	}

	return vc, nil
}

func getAttachmentURIs(attachments []*protocol.AnchorDocument) []string {
	var attachURIs []string

	for _, attach := range attachments {
		attachURIs = append(attachURIs, attach.ID)
	}

	return attachURIs
}

func (c *Writer) signCredential(vc *verifiable.Credential, witnesses []string) (*verifiable.Credential, error) {
	signCredentialStartTime := time.Now()

	defer c.metrics.WriteAnchorSignCredentialTime(time.Since(signCredentialStartTime))

	if c.Witness != nil && (contains(witnesses, c.apServiceIRI.String()) || c.signWithLocalWitness) {
		return c.signCredentialWithLocalWitnessLog(vc)
	}

	return c.signCredentialWithServerKey(vc)
}

func contains(values []string, v string) bool {
	for _, val := range values {
		if val == v {
			return true
		}
	}

	return false
}

func (c *Writer) signCredentialWithServerKey(vc *verifiable.Credential) (*verifiable.Credential, error) {
	startTime := time.Now()
	defer func() { c.metrics.WriteAnchorSignWithServerKeyTime(time.Since(startTime)) }()

	signedVC, err := c.Signer.Sign(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign anchor credential[%s]: %w", vc.ID, err)
	}

	return signedVC, nil
}

func (c *Writer) signCredentialWithLocalWitnessLog(vc *verifiable.Credential) (*verifiable.Credential, error) {
	startTime := time.Now()
	defer func() { c.metrics.WriteAnchorSignWithLocalWitnessTime(time.Since(startTime)) }()

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal anchor credential[%s] for local witness: %w", vc.ID, err)
	}

	logger.Debugf("sign credential with local witness: %s", string(vcBytes))

	witnessStartTime := time.Now()
	// send anchor credential to local witness log
	proofBytes, err := c.Witness.Witness(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("local witnessing failed for anchor credential[%s]: %w", vc.ID, err)
	}

	c.metrics.WriteAnchorSignLocalWitnessLogTime(time.Since(witnessStartTime))

	var witnessProof vct.Proof

	err = json.Unmarshal(proofBytes, &witnessProof)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal local witness proof for anchor credential[%s]: %w", vc.ID, err)
	}

	vc.Proofs = append(vc.Proofs, witnessProof.Proof)

	var (
		createdTime time.Time
		domain      string
	)

	if created, ok := witnessProof.Proof["created"].(string); ok {
		createdTime, err = time.Parse(time.RFC3339, created)
		if err != nil {
			return nil, fmt.Errorf("parse created: %w", err)
		}
	}

	if domainVal, ok := witnessProof.Proof["domain"].(string); ok {
		domain = domainVal
	}

	watchStartTime := time.Now()

	err = c.MonitoringSvc.Watch(vc, time.Now().Add(c.maxWitnessDelay), domain, createdTime)
	if err != nil {
		return nil, fmt.Errorf("failed to setup monitoring for local witness for anchor credential[%s]: %w", vc.ID, err)
	}

	c.metrics.WriteAnchorSignLocalWatchTime(time.Since(watchStartTime))

	return vc, nil
}

func (c *Writer) handle(anchorEvent *vocab.AnchorEventType) error {
	logger.Debugf("handling witnessed anchor event: %s", anchorEvent.Index())

	startTime := time.Now()

	defer func() {
		c.metrics.ProcessWitnessedAnchorCredentialTime(time.Since(startTime))
	}()

	err := c.storeVC(anchorEvent)
	if err != nil {
		logger.Errorf("failed to store verifiable credential from anchor event[%s]: %s", anchorEvent.Index(), err.Error())

		return fmt.Errorf("store verifiable credential from anchor event[%s]: %w", anchorEvent.Index(), err)
	}

	anchorEventRef, err := c.AnchorGraph.Add(anchorEvent)
	if err != nil {
		logger.Errorf("failed to add witnessed anchor event[%s] to anchor graph: %s", anchorEvent.Index(), err.Error())

		return fmt.Errorf("add witnessed anchor event[%s] to anchor graph: %w", anchorEvent.Index(), err)
	}

	logger.Debugf("Publishing anchor event[%s] ref[%s]", anchorEvent.Index(), anchorEventRef)

	err = c.anchorPublisher.PublishAnchor(&anchorinfo.AnchorInfo{Hashlink: anchorEventRef})
	if err != nil {
		logger.Warnf("failed to publish anchor event[%s] ref[%s]: %s",
			anchorEvent.Index(), anchorEventRef, err.Error())

		return fmt.Errorf("publish anchor event[%s] ref [%s]: %w", anchorEvent.Index(), anchorEventRef, err)
	}

	err = c.WitnessStore.Delete(anchorEvent.Index().String())
	if err != nil {
		// this is a clean-up task so no harm if there was an error
		logger.Warnf("failed to delete witnesses for anchor event[%s] ref[%s]: %s",
			anchorEvent.Index(), anchorEventRef, err.Error())
	}

	err = c.AnchorEventStore.Delete(anchorEvent.Index().String())
	if err != nil {
		// this is a clean-up task so no harm if there was an error
		logger.Warnf("failed to delete anchor event[%s]: %s", anchorEvent.Index(), err.Error())
	}

	logger.Debugf("Posting anchor event[%s] ref[%s] to my followers.", anchorEvent.Index(), anchorEventRef)

	// announce anchor credential activity to followers
	err = c.postCreateActivity(anchorEvent, anchorEventRef)
	if err != nil {
		logger.Warnf("failed to post new create activity for anchor event[%s] ref[%s]: %s",
			anchorEvent.Index(), anchorEventRef, err.Error())

		// Don't return a transient error since the anchor has already been published and we don't want to trigger a retry.
		return fmt.Errorf("post create activity for anchor event[%s] ref[%s]: %w",
			anchorEvent.Index(), anchorEventRef, err)
	}

	return nil
}

func (c *Writer) storeVC(anchorEvent *vocab.AnchorEventType) error {
	vc, err := util.VerifiableCredentialFromAnchorEvent(anchorEvent,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.DocumentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor event: %w", err)
	}

	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("failed to marshal vc[%s]: %w", vc.ID, err)
	}

	parts := strings.Split(vc.ID, "/")
	id := parts[len(parts)-1]

	err = c.VCStore.Put(id, vcBytes)
	if err != nil {
		return fmt.Errorf("failed to store vc[%s]: %w", id, err)
	}

	return nil
}

// postCreateActivity creates and posts create activity (announces anchor credential to followers).
func (c *Writer) postCreateActivity(anchorEvent *vocab.AnchorEventType, hl string) error { //nolint: interfacer
	systemFollowers, err := url.Parse(c.apServiceIRI.String() + resthandler.FollowersPath)
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	hlURL, err := url.Parse(hl)
	if err != nil {
		return fmt.Errorf("parse hashlink: %w", err)
	}

	// Create a new Info that includes the hashlink of where this activity is stored,
	// so that a server that's processing this event may resolve the Info from the hashlink.
	anchorEvent = vocab.NewAnchorEvent(
		vocab.WithURL(hlURL),
		vocab.WithAttributedTo(anchorEvent.AttributedTo().URL()),
		vocab.WithIndex(anchorEvent.Index()),
		vocab.WithPublishedTime(anchorEvent.Published()),
		vocab.WithParent(anchorEvent.Parent()...),
		vocab.WithAttachment(anchorEvent.Attachment()...),
	)

	now := time.Now()

	create := vocab.NewCreateActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)),
		vocab.WithContext(vocab.ContextActivityAnchors),
		vocab.WithTo(systemFollowers, vocab.PublicIRI),
		vocab.WithPublishedTime(&now),
	)

	postID, err := c.Outbox.Post(create)
	if err != nil {
		return err
	}

	logger.Debugf("Successfully posted 'Create' activity to my followers [%s]", postID)

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Writer) postOfferActivity(anchorEvent *vocab.AnchorEventType, localProof vocab.Document,
	batchWitnesses []string) error {
	postOfferActivityStartTime := time.Now()

	defer c.metrics.WriteAnchorPostOfferActivityTime(time.Since(postOfferActivityStartTime))

	logger.Debugf("sending anchor event[%s] to system witnesses plus: %s", anchorEvent.Index(), batchWitnesses)

	witnessesIRI, err := c.getWitnesses(anchorEvent.Index().String(), batchWitnesses)
	if err != nil {
		return fmt.Errorf("failed to get witnesses: %w", err)
	}

	witnessesIRI = append(witnessesIRI, vocab.PublicIRI)

	startTime := time.Now()
	endTime := startTime.Add(c.maxWitnessDelay)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(anchorEvent),
		),
		vocab.WithTo(witnessesIRI...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
	)

	postID, err := c.Outbox.Post(offer)
	if err != nil {
		return fmt.Errorf("failed to post offer for anchor index[%s]: %w", anchorEvent.Index(), err)
	}

	logger.Debugf("created pre-announce activity for anchor index[%s], post id[%s]", anchorEvent.Index(), postID)

	if len(witnessesIRI) == 1 {
		// The Offer was posted only to the public IRI. This means that it will be persisted
		// in the ActivityPub Outbox (to be viewed by anyone) but won't be sent to any service.
		// In this case we can handle the anchor event immediately.
		logger.Debugf("According to witness policy, no witnesses are required for anchor index[%s]. "+
			"Processing the anchor immediately.", anchorEvent.Index())

		localProofBytes, e := json.Marshal(localProof)
		if err != nil {
			return fmt.Errorf("marshal localProof: %w", e)
		}

		// Handle the anchor event by providing this service's proof.
		e = c.ProofHandler.HandleProof(c.apServiceIRI, anchorEvent.Index().String(), endTime, localProofBytes)
		if e != nil {
			return fmt.Errorf("handle offer with no witnesses: %w", e)
		}
	}

	return nil
}

// getWitnessesFromBatchOperations returns the list of anchor origins for all dids in the Sidetree batch.
// Create and recover operations contain anchor origin in operation references.
// For update and deactivate operations we have to 'resolve' did in order to figure out anchor origin.
func (c *Writer) getWitnessesFromBatchOperations(refs []*operation.Reference) ([]string, error) {
	getWitnessesStartTime := time.Now()

	defer c.metrics.WriteAnchorGetWitnessesTime(time.Since(getWitnessesStartTime))

	var witnesses []string

	uniqueWitnesses := make(map[string]bool)

	for _, ref := range refs {
		resolvedWitness, err := c.resolveWitness(ref)
		if err != nil {
			return nil, fmt.Errorf("resolve witness: %w", err)
		}

		_, ok := uniqueWitnesses[resolvedWitness]

		if !ok {
			witnesses = append(witnesses, resolvedWitness)
			uniqueWitnesses[resolvedWitness] = true
		}
	}

	return witnesses, nil
}

func (c *Writer) resolveWitness(ref *operation.Reference) (string, error) {
	var anchorOriginObj interface{}

	switch ref.Type {
	case operation.TypeCreate, operation.TypeRecover:
		anchorOriginObj = ref.AnchorOrigin

	case operation.TypeUpdate, operation.TypeDeactivate:
		anchorOriginObj = ref.AnchorOrigin

		if anchorOriginObj == nil {
			// currently anchor origin object should always be populated since we are checking that update, recover
			// and deactivate operations have previous valid operations (e.g. create) - if we decide to allow
			// those operations to go through during ingestion without checking for previous operations then anchor
			// origin object will not be set and we have to resolve document in order to get it
			result, err := c.OpProcessor.Resolve(ref.UniqueSuffix)
			if err != nil {
				return "", err
			}

			logger.Debugf("resolved anchor origin[%s] for operation type[%s] : %s", result.AnchorOrigin, ref.Type)

			anchorOriginObj = result.AnchorOrigin
		}

	default:
		return "", fmt.Errorf("operation type '%s' not supported for assembling witness list", ref.Type)
	}

	anchorOrigin, ok := anchorOriginObj.(string)
	if !ok {
		return "", fmt.Errorf("unexpected interface '%T' for anchor origin", anchorOriginObj)
	}

	logger.Debugf("Resolving witness for the following anchor origin: %s", anchorOrigin)

	resolveStartTime := time.Now()

	resolvedWitness, err := c.resourceResolver.ResolveHostMetaLink(anchorOrigin, discoveryrest.ActivityJSONType)
	if err != nil {
		return "", fmt.Errorf("failed to resolve witness: %w", err)
	}

	c.metrics.WriteAnchorResolveHostMetaLinkTime(time.Since(resolveStartTime))

	logger.Debugf("Successfully resolved witness %s from %s", resolvedWitness, anchorOrigin)

	return resolvedWitness, nil
}

// Read reads transactions since transaction time.
// TODO: This is not used and can be removed from interface if we change observer in sidetree-mock to point
// to core observer (can be done easily) Concern: Reference app has this interface.
func (c *Writer) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}

func (c *Writer) getWitnesses(anchorID string, batchOpsWitnesses []string) ([]*url.URL, error) {
	batchWitnesses, err := c.getBatchWitnesses(batchOpsWitnesses)
	if err != nil {
		return nil, err
	}

	systemWitnesses, err := c.getSystemWitnesses()
	if err != nil {
		return nil, err
	}

	var witnesses []*proof.Witness
	witnesses = append(witnesses, batchWitnesses...)
	witnesses = append(witnesses, systemWitnesses...)

	selectedWitnesses, err := c.WitnessPolicy.Select(witnesses)
	if err != nil {
		return nil, fmt.Errorf("select witnesses: %w", err)
	}

	selectedWitnessesIRI, selectedWitnessesMap := getUniqueWitnesses(selectedWitnesses)

	if len(selectedWitnesses) == 0 {
		logger.Debugf("No witnesses were configured. Adding self [%s] to witness list.", c.apServiceIRI)

		hasLog, e := c.WFClient.HasSupportedLedgerType(fmt.Sprintf("%s://%s", c.apServiceIRI.Scheme, c.apServiceIRI.Host))
		if e != nil {
			return nil, e
		}

		witness := &proof.Witness{
			URI:      c.apServiceIRI,
			HasLog:   hasLog,
			Selected: true,
		}

		witnesses = append(witnesses, witness)

		_, selectedWitnessesMap = getUniqueWitnesses([]*proof.Witness{witness})
	}

	// store witnesses before posting offers
	err = c.storeWitnesses(anchorID, updateWitnessSelectionFlag(witnesses, selectedWitnessesMap))
	if err != nil {
		return nil, fmt.Errorf("store witnesses: %w", err)
	}

	logger.Debugf("selected %d witnesses: %+v", len(selectedWitnessesIRI), selectedWitnessesIRI)

	return selectedWitnessesIRI, nil
}

func updateWitnessSelectionFlag(witnesses []*proof.Witness, selectedWitnesses map[string]bool) []*proof.Witness {
	for _, w := range witnesses {
		if _, ok := selectedWitnesses[w.URI.String()]; ok {
			w.Selected = true
		}
	}

	return witnesses
}

func getUniqueWitnesses(witnesses []*proof.Witness) ([]*url.URL, map[string]bool) {
	uniqueWitnesses := make(map[string]bool)

	var witnessesIRI []*url.URL

	for _, w := range witnesses {
		_, ok := uniqueWitnesses[w.URI.String()]
		if !ok {
			witnessesIRI = append(witnessesIRI, w.URI)
			uniqueWitnesses[w.URI.String()] = true
		}
	}

	return witnessesIRI, uniqueWitnesses
}

func (c *Writer) storeWitnesses(anchorID string, witnesses []*proof.Witness) error {
	err := c.WitnessStore.Put(anchorID, witnesses)
	if err != nil {
		return fmt.Errorf("failed to store witnesses for anchor event[%s]: %w", anchorID, err)
	}

	err = c.AnchorEventStatusStore.AddStatus(anchorID, proof.AnchorIndexStatusInProcess)
	if err != nil {
		return fmt.Errorf("failed to set 'in-process' status for anchor event[%s]: %w", anchorID, err)
	}

	return nil
}

func (c *Writer) getSystemWitnessesIRI() ([]*url.URL, error) {
	it, err := c.ActivityStore.QueryReferences(spi.Witness,
		spi.NewCriteria(
			spi.WithObjectIRI(c.apServiceIRI),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query references for system witnesses: %w", err)
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	systemWitnessesIRI, err := storeutil.ReadReferences(it, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to read system witnesses from iterator: %w", err)
	}

	logger.Debugf("configured system witnesses: %+v", systemWitnessesIRI)

	return systemWitnessesIRI, nil
}

func (c *Writer) getSystemWitnesses() ([]*proof.Witness, error) {
	systemWitnessesIRI, err := c.getSystemWitnessesIRI()
	if err != nil {
		return nil, err
	}

	var witnesses []*proof.Witness

	for _, systemWitnessIRI := range systemWitnessesIRI {
		domain := fmt.Sprintf("%s://%s", systemWitnessIRI.Scheme, systemWitnessIRI.Host)

		hasLog, innerErr := c.WFClient.HasSupportedLedgerType(domain)
		if innerErr != nil {
			return nil, innerErr
		}

		witnesses = append(witnesses,
			&proof.Witness{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessIRI,
				HasLog: hasLog,
			})
	}

	return witnesses, nil
}

func (c *Writer) getBatchWitnesses(batchWitnesses []string) ([]*proof.Witness, error) {
	var witnesses []*proof.Witness

	for _, batchWitness := range batchWitnesses {
		// do not add local domain as external witness
		if batchWitness == c.apServiceIRI.String() {
			continue
		}

		batchWitnessIRI, err := url.Parse(batchWitness)
		if err != nil {
			return nil, fmt.Errorf("failed to parse witness path[%s]: %w", batchWitness, err)
		}

		hasLog, err := c.WFClient.HasSupportedLedgerType(fmt.Sprintf("%s://%s", batchWitnessIRI.Scheme, batchWitnessIRI.Host))
		if err != nil {
			return nil, err
		}

		witnesses = append(witnesses,
			&proof.Witness{
				Type:   proof.WitnessTypeBatch,
				HasLog: hasLog,
				URI:    batchWitnessIRI,
			})
	}

	return witnesses, nil
}
