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
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-go/pkg/document"
	svcoperation "github.com/trustbloc/sidetree-svc-go/pkg/api/operation"
	svcprotocol "github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-svc-go/pkg/api/txn"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/multierror"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/datauri"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	docutil "github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	pubsubspi "github.com/trustbloc/orb/pkg/pubsub/spi"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/vct"
)

var logger = log.New("anchor-writer")

//nolint:interfacebloat
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
	HandleProof(ctx context.Context, witness *url.URL, anchorID string, endTime time.Time, proof []byte) error
}

type generatorRegistry interface {
	GetByNamespaceAndVersion(ns string, ver uint64) (generator.Generator, error)
}

type anchorLinkBuilder interface {
	BuildAnchorLink(payload *subject.Payload, dataURIMediaType datauri.MediaType,
		buildVC anchorlinkset.VCBuilder) (anchorLink *linkset.Link, vcBytes []byte, err error)
}

// Writer implements writing anchors.
type Writer struct {
	*Providers
	namespace            string
	anchorPublisher      anchorPublisher
	apServiceIRI         *url.URL
	apServiceEndpointURL *url.URL
	casIRI               *url.URL
	dataURIMediaType     vocab.MediaType
	maxWitnessDelay      time.Duration
	signWithLocalWitness bool
	resourceResolver     *resourceresolver.Resolver
	metrics              metricsProvider
	tracer               trace.Tracer
}

// Providers contains the providers required by the client.
type Providers struct {
	AnchorGraph            anchorGraph
	DidAnchors             didAnchors
	AnchorBuilder          anchorBuilder
	AnchorLinkStore        anchorStore
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
	GeneratorRegistry      generatorRegistry
	AnchorLinkBuilder      anchorLinkBuilder
}

type webfingerClient interface {
	HasSupportedLedgerType(uri string) (bool, error)
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
	Context() []string
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type outbox interface {
	Post(ctx context.Context, activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

type opProcessor interface {
	Resolve(uniqueSuffix string, opts ...document.ResolutionOption) (*protocol.ResolutionModel, error)
}

type anchorGraph interface {
	Add(anchorLink *linkset.Linkset) (string, error)
}

type anchorBuilder interface {
	Build(profile *url.URL, anchorHashlink, coreIndexHashlink string, context []string) (*verifiable.Credential, error)
}

type didAnchors interface {
	GetBulk(did []string) ([]string, error)
}

type anchorStore interface {
	Put(anchorLink *linkset.Link) error
	Delete(id string) error
}

type statusStore interface {
	AddStatus(vcID string, status proof.AnchorIndexStatus) error
}

type anchorPublisher interface {
	PublishAnchor(ctx context.Context, anchorInfo *anchorinfo.AnchorInfo) error
}

type pubSub interface {
	Publish(topic string, messages ...*message.Message) error
	SubscribeWithOpts(ctx context.Context, topic string, opts ...pubsubspi.Option) (<-chan *message.Message, error)
}

// New returns a new anchor writer.
func New(namespace string, apServiceIRI, apServiceEndpointURL, casURL *url.URL, dataURIMediaType vocab.MediaType,
	providers *Providers, anchorPublisher anchorPublisher, pubSub pubSub, maxWitnessDelay time.Duration,
	signWithLocalWitness bool, resourceResolver *resourceresolver.Resolver, subscriberPoolSize int,
	metrics metricsProvider,
) (*Writer, error) {
	logger.Info("Creating writer", logfields.WithNamespace(namespace), logfields.WithServiceIRI(apServiceIRI),
		logfields.WithSubscriberPoolSize(subscriberPoolSize), logfields.WithServiceEndpoint(apServiceEndpointURL.String()))

	w := &Writer{
		Providers:            providers,
		anchorPublisher:      anchorPublisher,
		namespace:            namespace,
		apServiceIRI:         apServiceIRI,
		apServiceEndpointURL: apServiceEndpointURL,
		casIRI:               casURL,
		maxWitnessDelay:      maxWitnessDelay,
		signWithLocalWitness: signWithLocalWitness,
		resourceResolver:     resourceResolver,
		metrics:              metrics,
		dataURIMediaType:     dataURIMediaType,
		tracer:               tracing.Tracer(tracing.SubsystemAnchor),
	}

	s, err := vcpubsub.NewSubscriber(pubSub, w.handle, subscriberPoolSize)
	if err != nil {
		return nil, fmt.Errorf("new subscriber: %w", err)
	}

	s.Start()

	return w, nil
}

// WriteAnchor writes Sidetree anchor string to Orb anchor.
func (c *Writer) WriteAnchor(anchor string, attachments []*svcprotocol.AnchorDocument,
	refs []*svcoperation.Reference, version uint64,
) error {
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

	payload := &subject.Payload{
		OperationCount:  ad.OperationCount,
		CoreIndex:       ad.CoreIndexFileURI,
		Namespace:       c.namespace,
		Version:         version,
		PreviousAnchors: previousAnchors,
		Attachments:     getAttachmentURIs(attachments),
		AnchorOrigin:    c.apServiceIRI.String(),
	}

	// figure out witness list for this anchor file
	batchWitnesses, err := c.getWitnessesFromBatchOperations(refs)
	if err != nil {
		return fmt.Errorf("failed to create witness list: %w", err)
	}

	anchorLink, vcBytes, err := c.buildAnchorLink(payload, batchWitnesses)
	if err != nil {
		return fmt.Errorf("build anchor linkset for core index [%s]: %w", payload.CoreIndex, err)
	}

	storeStartTime := time.Now()

	err = c.AnchorLinkStore.Put(anchorLink)
	if err != nil {
		return fmt.Errorf("store anchor event: %w", err)
	}

	c.metrics.WriteAnchorStoreTime(time.Since(storeStartTime))

	logger.Debug("Signed and stored anchor object",
		logfields.WithCoreIndex(payload.CoreIndex), logfields.WithAnchorURI(anchorLink.Anchor()))

	ctx, span := c.tracer.Start(context.Background(), "write anchor")
	defer span.End()

	// send an offer activity to witnesses (request witnessing anchor credential from non-local witness logs)
	err = c.postOfferActivity(ctx, anchorLink, vcBytes, batchWitnesses)
	if err != nil {
		return fmt.Errorf("failed to post new offer activity for core index[%s]: %w",
			payload.CoreIndex, err)
	}

	return nil
}

func (c *Writer) buildAnchorLink(payload *subject.Payload,
	witnesses []string,
) (anchorLink *linkset.Link, vcBytes []byte, err error) {
	return c.AnchorLinkBuilder.BuildAnchorLink(payload, c.dataURIMediaType,
		func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error) {
			buildCredStartTime := time.Now()

			defer c.metrics.WriteAnchorBuildCredentialTime(time.Since(buildCredStartTime))

			gen, err := c.GeneratorRegistry.GetByNamespaceAndVersion(payload.Namespace, payload.Version)
			if err != nil {
				return nil, fmt.Errorf("get generator: %w", err)
			}

			vc, err := c.AnchorBuilder.Build(gen.ID(), anchorHashlink, coreIndexHashlink, c.Signer.Context())
			if err != nil {
				return nil, fmt.Errorf("build anchor credential: %w", err)
			}

			// sign credential using local witness log or server public key
			vc, err = c.signCredential(vc, witnesses)
			if err != nil {
				return nil, fmt.Errorf("sign credential: %w", err)
			}

			return vc, nil
		},
	)
}

func (c *Writer) getPreviousAnchors(refs []*svcoperation.Reference) ([]*subject.SuffixAnchor, error) {
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

	mErr := multierror.New()

	for i, ref := range refs {
		if anchors[i] == "" {
			if ref.Type != operation.TypeCreate {
				mErr.Set(ref.UniqueSuffix,
					fmt.Errorf("previous did anchor reference not found for %s operation for did[%s]",
						ref.Type, ref.UniqueSuffix))
			} else {
				// create doesn't have previous anchor references
				previousAnchors = append(previousAnchors, &subject.SuffixAnchor{Suffix: ref.UniqueSuffix})
			}
		} else {
			previousAnchors = append(previousAnchors, &subject.SuffixAnchor{Suffix: ref.UniqueSuffix, Anchor: anchors[i]})
		}
	}

	if len(mErr.Errors()) > 0 {
		return nil, mErr
	}

	return previousAnchors, nil
}

func getSuffixes(refs []*svcoperation.Reference) []string {
	suffixes := make([]string, len(refs))
	for i, ref := range refs {
		suffixes[i] = ref.UniqueSuffix
	}

	return suffixes
}

func getAttachmentURIs(attachments []*svcprotocol.AnchorDocument) []string {
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

	for _, signerCtx := range c.Signer.Context() {
		exist := false

		for _, vcCtx := range vc.Context {
			if vcCtx == signerCtx {
				exist = true

				break
			}
		}

		if !exist {
			vc.Context = append(vc.Context, signerCtx)
		}
	}

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

	logger.Debug("Sign credential with local witness", logfields.WithVerifiableCredential(vcBytes))

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

func (c *Writer) handle(ctx context.Context, anchorLinkset *linkset.Linkset) error {
	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return fmt.Errorf("anchor Linkset is empty")
	}

	logger.Debug("Handling witnessed anchor", logfields.WithAnchorURI(anchorLink.Anchor()))

	startTime := time.Now()

	defer func() {
		c.metrics.ProcessWitnessedAnchorCredentialTime(time.Since(startTime))
	}()

	err := c.storeVC(anchorLink)
	if err != nil {
		return fmt.Errorf("store verifiable credential from anchor event[%s]: %w", anchorLink.Anchor(), err)
	}

	anchorLinksetHL, err := c.AnchorGraph.Add(anchorLinkset)
	if err != nil {
		return fmt.Errorf("add witnessed anchor[%s] to anchor graph: %w", anchorLink.Anchor(), err)
	}

	logger.Debug("Publishing anchor", logfields.WithAnchorURI(anchorLink.Anchor()),
		logfields.WithAnchorEventURIString(anchorLinksetHL))

	err = c.anchorPublisher.PublishAnchor(ctx, &anchorinfo.AnchorInfo{Hashlink: anchorLinksetHL})
	if err != nil {
		return fmt.Errorf("publish anchor[%s] ref [%s]: %w", anchorLink.Anchor(), anchorLinksetHL, err)
	}

	err = c.deleteTransientData(anchorLink)
	if err != nil {
		// this is a clean-up task so no harm if there was an error
		logger.Warn("Error deleting transient data for anchor", logfields.WithAnchorURI(anchorLink.Anchor()), log.WithError(err))
	}

	logger.Debug("Posting anchor reference(s) to my followers.", logfields.WithAnchorURI(anchorLink.Anchor()),
		logfields.WithAnchorEventURIString(anchorLinksetHL))

	// announce anchor credential activity to followers
	err = c.postCreateActivity(ctx, anchorLinkset, anchorLinksetHL)
	if err != nil {
		// Don't return a transient error since the anchor has already been published and we don't want to trigger a retry.
		return fmt.Errorf("post create activity for anchor[%s] ref[%s]: %w",
			anchorLink.Anchor(), anchorLinksetHL, err)
	}

	return nil
}

func (c *Writer) deleteTransientData(anchorLink *linkset.Link) error {
	if err := c.WitnessStore.Delete(anchorLink.Anchor().String()); err != nil {
		return fmt.Errorf("failed to delete witnesses for anchor[%s]: %w", anchorLink.Anchor(), err)
	}

	if err := c.AnchorLinkStore.Delete(anchorLink.Anchor().String()); err != nil {
		return fmt.Errorf("failed to delete anchor[%s]: %w", anchorLink.Anchor(), err)
	}

	return nil
}

func (c *Writer) storeVC(anchorLink *linkset.Link) error {
	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLink,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.DocumentLoader),
		verifiable.WithStrictValidation(),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor link: %w", err)
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
func (c *Writer) postCreateActivity(ctx context.Context, anchorLinkset *linkset.Linkset, hl string) error { //nolint: interfacer
	systemFollowers, err := url.Parse(c.apServiceEndpointURL.String() + resthandler.FollowersPath)
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	hlURL, err := url.Parse(hl)
	if err != nil {
		return fmt.Errorf("parse hashlink: %w", err)
	}

	anchorLinksetDoc, err := vocab.MarshalToDoc(anchorLinkset)
	if err != nil {
		return fmt.Errorf("marshal anchor Linkset: %w", err)
	}

	// Create an AnchorEvent that includes the hashlink of where the anchor linkset is stored
	// so that a server processing this activity may resolve the anchor link from the hashlink.
	anchorEvent := vocab.NewAnchorEvent(
		vocab.NewObjectProperty(vocab.WithDocument(anchorLinksetDoc)),
		vocab.WithURL(hlURL),
	)

	now := time.Now()

	create := vocab.NewCreateActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)),
		vocab.WithTo(systemFollowers, vocab.PublicIRI),
		vocab.WithPublishedTime(&now),
	)

	activityID, err := c.Outbox.Post(ctx, create)
	if err != nil {
		return err
	}

	logger.Debug("Successfully posted 'Create' activity to my followers", logfields.WithActivityID(activityID))

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Writer) postOfferActivity(ctx context.Context, anchorLink *linkset.Link, localProofBytes []byte, batchWitnesses []string) error {
	postOfferActivityStartTime := time.Now()

	defer c.metrics.WriteAnchorPostOfferActivityTime(time.Since(postOfferActivityStartTime))

	logger.Debug("Sending anchor linkset to system and batch witnesses",
		logfields.WithAnchorURI(anchorLink.Anchor()), logfields.WithWitnessURIStrings(batchWitnesses...))

	selectedWitnessesIRIs, allWitnesses, err := c.getWitnesses(batchWitnesses)
	if err != nil {
		return fmt.Errorf("failed to get witnesses: %w", err)
	}

	selectedWitnessesIRIs = append(selectedWitnessesIRIs, vocab.PublicIRI)

	startTime := time.Now()
	endTime := startTime.Add(c.maxWitnessDelay)

	anchorLinksetDoc, err := vocab.MarshalToDoc(linkset.New(anchorLink))
	if err != nil {
		return fmt.Errorf("marshal anchor linkset: %w", err)
	}

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithDocument(anchorLinksetDoc)),
		vocab.WithTo(selectedWitnessesIRIs...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
	)

	activityID, err := c.Outbox.Post(ctx, offer)
	if err != nil {
		return fmt.Errorf("failed to post offer for anchor[%s]: %w", anchorLink.Anchor(), err)
	}

	err = c.storeWitnesses(anchorLink.Anchor().String(), allWitnesses)
	if err != nil {
		return fmt.Errorf("store witnesses: %w", err)
	}

	logger.Info("Posted 'Offer' activity to witnesses", logfields.WithAnchorURI(anchorLink.Anchor()),
		logfields.WithActivityID(activityID), logfields.WithWitnessURIs(selectedWitnessesIRIs...))

	if len(selectedWitnessesIRIs) == 1 {
		// The Offer was posted only to the public IRI. This means that it will be persisted
		// in the ActivityPub Outbox (to be viewed by anyone) but won't be sent to any service.
		// In this case we can handle the anchor event immediately.
		logger.Debug("According to witness policy, no witnesses are required for the anchor. "+
			"Processing the anchor immediately.", logfields.WithAnchorURI(anchorLink.Anchor()))

		if len(localProofBytes) == 0 {
			return fmt.Errorf("no local proof for anchor [%s]", anchorLink.Anchor())
		}

		// Handle the anchor event by providing this service's proof.
		e := c.ProofHandler.HandleProof(ctx, c.apServiceIRI, anchorLink.Anchor().String(), endTime, localProofBytes)
		if e != nil {
			return fmt.Errorf("handle offer with no witnesses: %w", e)
		}
	}

	return nil
}

// getWitnessesFromBatchOperations returns the list of anchor origins for all dids in the Sidetree batch.
// Create and recover operations contain anchor origin in operation references.
// For update and deactivate operations we have to 'resolve' did in order to figure out anchor origin.
func (c *Writer) getWitnessesFromBatchOperations(refs []*svcoperation.Reference) ([]string, error) {
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

func (c *Writer) resolveWitness(ref *svcoperation.Reference) (string, error) {
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
				return "", fmt.Errorf("resolve unique suffix [%s]: %w", ref.UniqueSuffix, err)
			}

			logger.Debug("Resolved anchor origin for operation",
				logfields.WithAnchorOrigin(result.AnchorOrigin), logfields.WithOperationType(string(ref.Type)))

			anchorOriginObj = result.AnchorOrigin
		}

	default:
		return "", fmt.Errorf("operation type '%s' not supported for assembling witness list", ref.Type)
	}

	anchorOrigin, ok := anchorOriginObj.(string)
	if !ok {
		return "", fmt.Errorf("unexpected interface '%T' for anchor origin", anchorOriginObj)
	}

	resolvedWitness := anchorOrigin

	if !docutil.IsDID(anchorOrigin) {
		logger.Debug("Resolving witness for anchor origin", logfields.WithAnchorOrigin(anchorOrigin))

		resolveStartTime := time.Now()

		var err error

		resolvedWitness, err = c.resourceResolver.ResolveHostMetaLink(anchorOrigin, discoveryrest.ActivityJSONType)
		if err != nil {
			return "", fmt.Errorf("failed to resolve witness: %w", err)
		}

		c.metrics.WriteAnchorResolveHostMetaLinkTime(time.Since(resolveStartTime))
	}

	logger.Debug("Successfully resolved witness for anchor origin",
		logfields.WithWitnessURIString(resolvedWitness), logfields.WithAnchorOrigin(anchorOrigin))

	return resolvedWitness, nil
}

// Read reads transactions since transaction time.
// TODO: This is not used and can be removed from interface if we change observer in sidetree-mock to point
// to core observer (can be done easily) Concern: Reference app has this interface.
func (c *Writer) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}

func (c *Writer) getWitnesses(batchOpsWitnesses []string) (selectedWitnessesIRI []*url.URL,
	witnesses []*proof.Witness, err error,
) {
	batchWitnesses, err := c.getBatchWitnesses(batchOpsWitnesses)
	if err != nil {
		return nil, nil, err
	}

	systemWitnesses, err := c.getSystemWitnesses()
	if err != nil {
		return nil, nil, err
	}

	witnesses = append(witnesses, batchWitnesses...)
	witnesses = append(witnesses, systemWitnesses...)

	selectedWitnesses, err := c.WitnessPolicy.Select(witnesses)
	if err != nil {
		return nil, nil, fmt.Errorf("select witnesses: %w", err)
	}

	selectedWitnessesIRI, selectedWitnessesMap := getUniqueWitnesses(selectedWitnesses)

	if len(selectedWitnesses) == 0 {
		logger.Debug("No witnesses were configured. Adding self to witness list.",
			logfields.WithWitnessURI(c.apServiceIRI))

		hasLog, e := c.WFClient.HasSupportedLedgerType(c.apServiceIRI.String())
		if e != nil {
			return nil, nil, e
		}

		witness := &proof.Witness{
			URI:      vocab.NewURLProperty(c.apServiceIRI),
			HasLog:   hasLog,
			Selected: true,
		}

		witnesses = append(witnesses, witness)

		_, selectedWitnessesMap = getUniqueWitnesses([]*proof.Witness{witness})
	}

	logger.Debug("Selected witnesses", logfields.WithTotal(len(selectedWitnessesIRI)),
		logfields.WithWitnessURIs(selectedWitnessesIRI...))

	return selectedWitnessesIRI, updateWitnessSelectionFlag(witnesses, selectedWitnessesMap), nil
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
			witnessesIRI = append(witnessesIRI, w.URI.URL())
			uniqueWitnesses[w.URI.String()] = true
		}
	}

	return witnessesIRI, uniqueWitnesses
}

func (c *Writer) storeWitnesses(anchorID string, witnesses []*proof.Witness) error {
	err := c.WitnessStore.Put(anchorID, witnesses)
	if err != nil {
		return fmt.Errorf("failed to store witnesses for anchor[%s]: %w", anchorID, err)
	}

	err = c.AnchorEventStatusStore.AddStatus(anchorID, proof.AnchorIndexStatusInProcess)
	if err != nil {
		return fmt.Errorf("failed to set 'in-process' status for anchor[%s]: %w", anchorID, err)
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
			log.CloseIteratorError(logger, err)
		}
	}()

	systemWitnessesIRI, err := storeutil.ReadReferences(it, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to read system witnesses from iterator: %w", err)
	}

	logger.Debug("Configured system witnesses", logfields.WithWitnessURIs(systemWitnessesIRI...))

	return systemWitnessesIRI, nil
}

func (c *Writer) getSystemWitnesses() ([]*proof.Witness, error) {
	systemWitnessesIRI, err := c.getSystemWitnessesIRI()
	if err != nil {
		return nil, err
	}

	var witnesses []*proof.Witness

	for _, systemWitnessIRI := range systemWitnessesIRI {
		hasLog, innerErr := c.WFClient.HasSupportedLedgerType(systemWitnessIRI.String())
		if innerErr != nil {
			logger.Warn("Skipping system witness since an error occurred while determining its ledger types",
				logfields.WithWitnessURI(systemWitnessIRI), log.WithError(err))

			continue
		}

		witnesses = append(witnesses,
			&proof.Witness{
				Type:   proof.WitnessTypeSystem,
				URI:    vocab.NewURLProperty(systemWitnessIRI),
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

		hasLog, err := c.WFClient.HasSupportedLedgerType(batchWitness)
		if err != nil {
			logger.Warn("Skipping batch witness since an error occurred while determining its ledger types",
				logfields.WithWitnessURIString(batchWitness), log.WithError(err))

			continue
		}

		witnesses = append(witnesses,
			&proof.Witness{
				Type:   proof.WitnessTypeBatch,
				HasLog: hasLog,
				URI:    vocab.NewURLProperty(batchWitnessIRI),
			})
	}

	return witnesses, nil
}
