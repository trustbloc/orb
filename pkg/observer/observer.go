/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("orb-observer")

const (
	defaultSubscriberPoolSize = 5

	defaultMonitoringSvcExpiry = 30 * time.Minute
)

// AnchorGraph interface to access anchors.
type AnchorGraph interface {
	Read(hl string) (*linkset.Linkset, error)
	GetDidAnchors(cid, suffix string) ([]graph.Anchor, error)
}

// OperationStore interface to access operation store.
type OperationStore interface {
	Put(ops []*operation.AnchoredOperation) error
}

// OperationFilter filters out operations before they are persisted.
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*operation.AnchoredOperation) ([]*operation.AnchoredOperation, error)
}

type didAnchors interface {
	// areNew may be used by an implementation to speed up how long the storage call takes.
	// The length of dids and areNew must match.
	PutBulk(dids []string, areNew []bool, cid string) error
}

// Publisher publishes anchors and DIDs to a message queue for processing.
type Publisher interface {
	PublishAnchor(ctx context.Context, anchorInfo *anchorinfo.AnchorInfo) error
	PublishDID(ctx context.Context, did string) error
}

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

type metricsProvider interface {
	ProcessAnchorTime(value time.Duration)
	ProcessDIDTime(value time.Duration)
}

// Outbox defines an ActivityPub outbox.
type Outbox interface {
	Post(ctx context.Context, activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
}

type resourceResolver interface {
	ResolveHostMetaLink(uri, linkType string) (string, error)
}

type casResolver interface {
	Resolve(webCASURL *url.URL, hl string, data []byte) ([]byte, string, error)
}

type documentLoader interface {
	LoadDocument(u string) (*ld.RemoteDocument, error)
}

type anchorLinkStore interface {
	PutLinks(links []*url.URL) error
	GetLinks(anchorHash string) ([]*url.URL, error)
	DeletePendingLinks(links []*url.URL) error
}

type anchorLinksetBuilder interface {
	GetPayloadFromAnchorLink(anchorLink *linkset.Link) (*subject.Payload, error)
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type outboxProvider func() Outbox

type options struct {
	discoveryDomain          string
	subscriberPoolSize       int
	proofMonitoringSvcExpiry time.Duration
}

// Option is an option for observer.
type Option func(opts *options)

// WithDiscoveryDomain sets optional discovery domain hint (used for did equivalent ids).
func WithDiscoveryDomain(domain string) Option {
	return func(opts *options) {
		opts.discoveryDomain = domain
	}
}

// WithSubscriberPoolSize sets the size of the message queue subscriber pool.
func WithSubscriberPoolSize(value int) Option {
	return func(opts *options) {
		opts.subscriberPoolSize = value
	}
}

// WithProofMonitoringExpiryPeriod sets expiry period for proof monitoring service.
func WithProofMonitoringExpiryPeriod(value time.Duration) Option {
	return func(opts *options) {
		opts.proofMonitoringSvcExpiry = value
	}
}

// Providers contains all of the providers required by the observer.
type Providers struct {
	ProtocolClientProvider protocol.ClientProvider
	AnchorGraph
	DidAnchors           didAnchors
	PubSub               pubSub
	Metrics              metricsProvider
	Outbox               outboxProvider
	HostMetaLinkResolver resourceResolver
	CASResolver          casResolver
	DocLoader            documentLoader
	Pkf                  verifiable.PublicKeyFetcher
	AnchorLinkStore      anchorLinkStore
	MonitoringSvc        monitoringSvc
	AnchorLinksetBuilder anchorLinksetBuilder
}

// Observer receives transactions over a channel and processes them by storing them to an operation store.
type Observer struct {
	*Providers

	serviceIRI          *url.URL
	pubSub              *PubSub
	discoveryDomain     string
	monitoringSvcExpiry time.Duration
}

// New returns a new observer.
func New(serviceIRI *url.URL, providers *Providers, opts ...Option) (*Observer, error) {
	optns := &options{
		proofMonitoringSvcExpiry: defaultMonitoringSvcExpiry,
	}

	for _, opt := range opts {
		opt(optns)
	}

	o := &Observer{
		serviceIRI:          serviceIRI,
		Providers:           providers,
		discoveryDomain:     optns.discoveryDomain,
		monitoringSvcExpiry: optns.proofMonitoringSvcExpiry,
	}

	subscriberPoolSize := optns.subscriberPoolSize
	if subscriberPoolSize == 0 {
		subscriberPoolSize = defaultSubscriberPoolSize
	}

	ps, err := NewPubSub(providers.PubSub, o.handleAnchor, o.processDID, subscriberPoolSize)
	if err != nil {
		return nil, err
	}

	o.pubSub = ps

	return o, nil
}

// Start starts observer routines.
func (o *Observer) Start() {
	o.pubSub.Start()
}

// Stop stops the observer.
func (o *Observer) Stop() {
	o.pubSub.Stop()
}

// Publisher returns the publisher that adds anchors and DIDs to a message queue for processing.
func (o *Observer) Publisher() Publisher {
	return o.pubSub
}

func (o *Observer) handleAnchor(ctx context.Context, anchor *anchorinfo.AnchorInfo) error {
	logger.Debug("Observing anchor", logfields.WithAnchorEventURIString(anchor.Hashlink),
		logfields.WithLocalHashlink(anchor.LocalHashlink), logfields.WithAttributedTo(anchor.AttributedTo))

	startTime := time.Now()

	defer func() {
		o.Metrics.ProcessAnchorTime(time.Since(startTime))
	}()

	anchorLinkset, err := o.AnchorGraph.Read(anchor.Hashlink)
	if err != nil {
		logger.Warn("Failed to get anchor Linkset from anchor graph",
			logfields.WithAnchorEventURIString(anchor.Hashlink), log.WithError(err))

		return err
	}

	logger.Debug("Successfully read anchor Linkset from anchor graph", logfields.WithAnchorEventURIString(anchor.Hashlink))

	for _, anchorLink := range anchorLinkset.Linkset {
		if err := o.processAnchor(ctx, anchor, anchorLink); err != nil {
			logger.Warn("Error processing anchor", logfields.WithAnchorEventURIString(anchor.Hashlink), log.WithError(err))

			if !orberrors.IsTransient(err) {
				logger.Info("Deleting pending anchor links", logfields.WithAnchorEventURIString(anchor.Hashlink))

				// This is a persistent error. Delete any pending link.
				if u, e := url.Parse(anchor.Hashlink); e != nil {
					logger.Warn("Error deleting pending links", logfields.WithAnchorEventURIString(anchor.Hashlink))
				} else if e := o.AnchorLinkStore.DeletePendingLinks([]*url.URL{u}); e != nil {
					logger.Warn("Error deleting pending links", logfields.WithAnchorEventURIString(anchor.Hashlink))
				}
			}

			return err
		}
	}

	return nil
}

func (o *Observer) processDID(ctx context.Context, did string) error {
	logger.Debug("Processing out-of-system DID", logfields.WithDID(did))

	startTime := time.Now()

	defer func() {
		o.Metrics.ProcessDIDTime(time.Since(startTime))
	}()

	cidWithHint, suffix, err := getDidParts(did)
	if err != nil {
		logger.Warn("Process DID failed", logfields.WithDID(did), log.WithError(err))

		return err
	}

	anchors, err := o.AnchorGraph.GetDidAnchors(cidWithHint, suffix)
	if err != nil {
		logger.Warn("Process DID failed", logfields.WithDID(did), log.WithError(err))

		return err
	}

	logger.Debug("Got anchors for out-of-system DID", logfields.WithTotal(len(anchors)), logfields.WithDID(did))

	for _, anchor := range anchors {
		logger.Debug("Processing anchor for out-of-system DID", logfields.WithAnchorCID(anchor.CID), logfields.WithDID(did))

		if err := o.processAnchor(ctx,
			&anchorinfo.AnchorInfo{Hashlink: anchor.CID},
			anchor.Info, suffix); err != nil {
			if orberrors.IsTransient(err) {
				// Return an error so that the message is redelivered and retried.
				return fmt.Errorf("process out-of-system anchor [%s]: %w", anchor.CID, err)
			}

			logger.Warn("Ignoring anchor for DID", logfields.WithAnchorCID(anchor.CID), logfields.WithDID(did), log.WithError(err))

			continue
		}
	}

	return nil
}

func getDidParts(did string) (cid, suffix string, err error) {
	const delimiter = ":"

	pos := strings.LastIndex(did, delimiter)
	if pos == -1 {
		return "", "", fmt.Errorf("invalid number of parts for did[%s]", did)
	}

	return did[0:pos], did[pos+1:], nil
}

//nolint:funlen,cyclop
func (o *Observer) processAnchor(ctx context.Context,
	anchor *anchorinfo.AnchorInfo, anchorLink *linkset.Link,
	suffixes ...string,
) error {
	logger.Debug("Processing anchor", logfields.WithAnchorEventURIString(anchor.Hashlink),
		logfields.WithAttributedTo(anchor.AttributedTo), logfields.WithSuffixes(suffixes...))

	anchorPayload, err := o.AnchorLinksetBuilder.GetPayloadFromAnchorLink(anchorLink)
	if err != nil {
		return fmt.Errorf("failed to extract anchor payload from anchor[%s]: %w", anchor.Hashlink, err)
	}

	pc, err := o.ProtocolClientProvider.ForNamespace(anchorPayload.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get protocol client for namespace [%s]: %w", anchorPayload.Namespace, err)
	}

	v, err := pc.Get(anchorPayload.Version)
	if err != nil {
		return fmt.Errorf("failed to get protocol version for transaction time [%d]: %w",
			anchorPayload.Version, err)
	}

	ad := &util.AnchorData{OperationCount: anchorPayload.OperationCount, CoreIndexFileURI: anchorPayload.CoreIndex}

	canonicalID, err := hashlink.GetResourceHashFromHashLink(anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("failed to get canonical ID from hl[%s]: %w", anchor.Hashlink, err)
	}

	equivalentRefs := []string{anchor.Hashlink}
	if o.discoveryDomain != "" {
		// only makes sense to have discovery domain with webcas (may change with ipfs gateway requirements)
		equivalentRefs = append(equivalentRefs, "https:"+o.discoveryDomain+":"+canonicalID)
	}

	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLink,
		verifiable.WithPublicKeyFetcher(o.Pkf),
		verifiable.WithJSONLDDocumentLoader(o.DocLoader),
		verifiable.WithStrictValidation(),
	)
	if err != nil {
		return fmt.Errorf("get verifiable credential from anchor link: %w", err)
	}

	o.setupProofMonitoring(vc)

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:      uint64(vc.Issued.Unix()),
		AnchorString:         ad.GetAnchorString(),
		Namespace:            anchorPayload.Namespace,
		ProtocolVersion:      anchorPayload.Version,
		CanonicalReference:   canonicalID,
		EquivalentReferences: equivalentRefs,
		AlternateSources:     anchor.AlternateSources,
	}

	logger.Debug("Processing anchor", logfields.WithAnchorEventURIString(anchor.Hashlink),
		logfields.WithCoreIndex(anchorPayload.CoreIndex))

	numProcessed, err := v.TransactionProcessor().Process(sidetreeTxn, suffixes...)
	if err != nil {
		return fmt.Errorf("failed to process anchor[%s] core index[%s]: %w",
			anchor.Hashlink, anchorPayload.CoreIndex, err)
	}

	if numProcessed == 0 {
		// This could be a duplicate anchor. Check if we have already completely processed the anchor.
		processed, e := o.isAnchorEventProcessed(anchor.Hashlink)
		if e != nil {
			return fmt.Errorf("check if anchor event %s is processed: %w",
				anchor.Hashlink, e)
		}

		if processed {
			logger.Info("Ignoring anchor event since it has already been processed",
				logfields.WithAnchorEventURIString(anchor.Hashlink))

			return nil
		}

		logger.Info("No operations were processed for anchor event (probably because all operations in the "+
			"anchor were already processed from a duplicate anchor event) but the anchor event is missing "+
			"from storage. The anchor event will be processed (again) which may result in some duplicate key warnings "+
			"from the DB, but this shouldn't be a problem since those duplicates will be ignored.",
			logfields.WithAnchorEventURIString(anchor.Hashlink))
	}

	// update global did/anchor references
	acSuffixes, areNewSuffixes := getSuffixes(anchorPayload.PreviousAnchors)

	err = o.DidAnchors.PutBulk(acSuffixes, areNewSuffixes, anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("failed updating did anchor references for anchor credential[%s]: %w", anchor.Hashlink, err)
	}

	logger.Info("Successfully processed DIDs in anchor", logfields.WithTotal(int(anchorPayload.OperationCount)),
		logfields.WithAnchorEventURIString(anchor.Hashlink), logfields.WithCoreIndex(anchorPayload.CoreIndex))

	// Post a 'Like' activity to the originator of the anchor credential.
	err = o.saveAnchorLinkAndPostLikeActivity(ctx, anchor)
	if err != nil {
		// This is not a critical error. We have already processed the anchor, so we don't want
		// to trigger a retry by returning a transient error. Just log a warning.
		logger.Warn("A 'Like' activity could not be posted to the outbox", log.WithError(err))
	}

	return nil
}

func (o *Observer) setupProofMonitoring(vc *verifiable.Credential) {
	expiryTime := time.Now().Add(o.monitoringSvcExpiry)

	// This code was moved from proof/credential handler to observer to make sure that monitoring is checked at all times
	// not just during anchor creation/publishing
	for _, proof := range getUniqueDomainCreated(vc.Proofs) {
		// getUniqueDomainCreated already checked that data is a string
		domain := proof["domain"].(string)   //nolint: forcetypeassert
		created := proof["created"].(string) //nolint: forcetypeassert

		createdTime, err := time.Parse(time.RFC3339, created)
		if err != nil {
			logger.Error("Failed to setup monitoring for anchor credential at proof domain.",
				logfields.WithVerifiableCredentialID(vc.ID), logfields.WithDomain(domain), log.WithError(err))

			continue
		}

		err = o.MonitoringSvc.Watch(vc, expiryTime, domain, createdTime)
		if err != nil {
			// This shouldn't be a fatal error since the anchor being processed may have multiple
			// witness proofs and, if one of the witness domains is down, it should not prevent the
			// anchor from being processed.
			logger.Error("Failed to setup monitoring for anchor credential at proof domain",
				logfields.WithVerifiableCredentialID(vc.ID), logfields.WithDomain(domain), log.WithError(err))
		} else {
			logger.Debug("Successfully setup monitoring for anchor credential at proof domain",
				logfields.WithVerifiableCredentialID(vc.ID), logfields.WithDomain(domain))
		}
	}
}

//nolint:cyclop
func (o *Observer) saveAnchorLinkAndPostLikeActivity(ctx context.Context, anchor *anchorinfo.AnchorInfo) error {
	refURL, err := url.Parse(anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("parse hash link [%s]: %w", anchor.Hashlink, err)
	}

	err = o.saveAnchorHashlink(refURL)
	if err != nil {
		// Not fatal.
		logger.Warn("Error saving anchor link", logfields.WithAnchorEventURI(refURL), log.WithError(err))
	}

	if anchor.AttributedTo == "" {
		logger.Debug("Not posting 'Like' activity since no attributedTo ID was specified for anchor",
			logfields.WithAnchorEventURI(refURL))

		return nil
	}

	attributedToEndpoint, err := o.resolveHostMetaLink(anchor.AttributedTo)
	if err != nil {
		return fmt.Errorf("resolve host meta-link for [%s]: %w", anchor.AttributedTo, err)
	}

	to := []*url.URL{attributedToEndpoint}

	// Also post a 'Like' to the creator of the anchor credential (if it's not the same as the actor above).
	originActorIRI, err := o.resolveActorFromHashlink(refURL.String())
	if err != nil {
		return fmt.Errorf("resolve origin actor for hashlink: %w", err)
	}

	if anchor.AttributedTo != originActorIRI && originActorIRI != o.serviceIRI.String() {
		originServiceEndpoint, e := o.resolveHostMetaLink(originActorIRI)
		if e != nil {
			return fmt.Errorf("resolve host meta-link: %w", e)
		}

		logger.Debug("Also posting a 'Like' to the origin of this activity",
			logfields.WithOriginActorID(originActorIRI), logfields.WithTargetIRI(originServiceEndpoint),
			logfields.WithAttributedTo(anchor.AttributedTo))

		to = append(to, originServiceEndpoint)
	}

	result, err := newLikeResult(anchor.LocalHashlink)
	if err != nil {
		return fmt.Errorf("new like result for local hashlink: %w", err)
	}

	err = o.doPostLikeActivity(ctx, to, refURL, result)
	if err != nil {
		return fmt.Errorf("post 'Like' activity to outbox for hashlink [%s]: %w", refURL, err)
	}

	return nil
}

func (o *Observer) doPostLikeActivity(ctx context.Context, to []*url.URL, refURL *url.URL, result *vocab.ObjectProperty) error {
	publishedTime := time.Now()

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(
			vocab.NewAnchorEvent(nil, vocab.WithURL(refURL)),
		)),
		vocab.WithTo(append(to, vocab.PublicIRI)...),
		vocab.WithPublishedTime(&publishedTime),
		vocab.WithResult(result),
	)

	if _, err := o.Outbox().Post(ctx, like); err != nil {
		return fmt.Errorf("post like: %w", err)
	}

	logger.Debug("Posted a 'Like' activity for anchor event", logfields.WithTargetIRIs(to...),
		logfields.WithAnchorEventURI(refURL))

	return nil
}

func (o *Observer) resolveActorFromHashlink(anchorRef string) (actorID string, err error) {
	anchorLinksetBytes, _, err := o.CASResolver.Resolve(nil, anchorRef, nil)
	if err != nil {
		return "", fmt.Errorf("resolve anchor: %w", err)
	}

	logger.Debug("Retrieved anchor", logfields.WithAnchorEventURIString(anchorRef),
		logfields.WithAnchorLinkset(anchorLinksetBytes))

	anchorLinkset := &linkset.Linkset{}

	err = json.Unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return "", fmt.Errorf("unmarshal anchor Linkset for [%s]: %w", anchorRef, err)
	}

	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return "", fmt.Errorf("empty anchor Linkset [%s]", anchorRef)
	}

	return anchorLink.Author().String(), nil
}

func (o *Observer) resolveHostMetaLink(uri string) (*url.URL, error) {
	endpoint, err := o.HostMetaLinkResolver.ResolveHostMetaLink(uri, discoveryrest.ActivityJSONType)
	if err != nil {
		return nil, fmt.Errorf("resolve host meta-link for [%s]: %w", uri, err)
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse URI [%s]: %w", endpoint, err)
	}

	return endpointURL, nil
}

// saveAnchorHashlink saves the hashlink of an anchor credential so that it may be returned
// in a WebFinger query as an alternate link.
func (o *Observer) saveAnchorHashlink(ref *url.URL) error {
	err := o.AnchorLinkStore.PutLinks([]*url.URL{ref})
	if err != nil {
		return fmt.Errorf("put anchor link [%s]: %w", ref, err)
	}

	logger.Debug("Saved anchor link", logfields.WithAnchorEventURI(ref))

	return nil
}

func (o *Observer) isAnchorEventProcessed(hl string) (bool, error) {
	hash, err := hashlink.GetResourceHashFromHashLink(hl)
	if err != nil {
		return false, fmt.Errorf("parse hashlink: %w", err)
	}

	links, err := o.AnchorLinkStore.GetLinks(hash)
	if err != nil {
		return false, fmt.Errorf("get anchor event: %w", err)
	}

	// There must be one link that matches the given hashlink.
	// (There may also be alternate links from 'Like' activities.)
	for _, link := range links {
		if link.String() == hl {
			return true, nil
		}
	}

	return false, nil
}

func getSuffixes(m []*subject.SuffixAnchor) (suffixes []string, areNewSuffixes []bool) {
	suffixes = make([]string, 0, len(m))
	// areNewSuffixes indicates whether the given suffix is from a create operation or not.
	// It's used to enable a faster BulkWrite call to the database.
	areNewSuffixes = make([]bool, 0, len(m))

	for _, k := range m {
		if k.Anchor == "" {
			areNewSuffixes = append(areNewSuffixes, true)
		} else {
			areNewSuffixes = append(areNewSuffixes, false)
		}

		suffixes = append(suffixes, k.Suffix)
	}

	return suffixes, areNewSuffixes
}

func newLikeResult(hashLink string) (*vocab.ObjectProperty, error) {
	if hashLink == "" {
		return nil, nil //nolint:nilnil
	}

	u, e := url.Parse(hashLink)
	if e != nil {
		return nil, fmt.Errorf("parse hashlink [%s]: %w", hashLink, e)
	}

	return vocab.NewObjectProperty(vocab.WithAnchorEvent(
		vocab.NewAnchorEvent(nil, vocab.WithURL(u))),
	), nil
}

func getUniqueDomainCreated(proofs []verifiable.Proof) []verifiable.Proof {
	var (
		set    = make(map[string]struct{})
		result []verifiable.Proof
	)

	for i := range proofs {
		domain, ok := proofs[i]["domain"].(string)
		if !ok {
			continue
		}

		created, ok := proofs[i]["created"].(string)
		if !ok {
			continue
		}

		if _, ok := set[domain+created]; ok {
			continue
		}

		set[domain+created] = struct{}{}

		result = append(result, proofs[i])
	}

	return result
}
