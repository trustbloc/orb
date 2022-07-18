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
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/errors"
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
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
	PublishDID(did string) error
}

type pubSub interface {
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
	Post(activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error)
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
}

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type outboxProvider func() Outbox

type options struct {
	discoveryDomain     string
	subscriberPoolSize  int
	monitoringSvcExpiry time.Duration
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

// WithMonitoringServiceExpiry sets expiry period for proof monitoring service.
func WithMonitoringServiceExpiry(value time.Duration) Option {
	return func(opts *options) {
		opts.monitoringSvcExpiry = value
	}
}

// Providers contains all of the providers required by the observer.
type Providers struct {
	ProtocolClientProvider protocol.ClientProvider
	AnchorGraph
	DidAnchors        didAnchors
	PubSub            pubSub
	Metrics           metricsProvider
	Outbox            outboxProvider
	WebFingerResolver resourceResolver
	CASResolver       casResolver
	DocLoader         documentLoader
	Pkf               verifiable.PublicKeyFetcher
	AnchorLinkStore   anchorLinkStore
	MonitoringSvc     monitoringSvc
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
		monitoringSvcExpiry: defaultMonitoringSvcExpiry,
	}

	for _, opt := range opts {
		opt(optns)
	}

	o := &Observer{
		serviceIRI:          serviceIRI,
		Providers:           providers,
		discoveryDomain:     optns.discoveryDomain,
		monitoringSvcExpiry: optns.monitoringSvcExpiry,
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

func (o *Observer) handleAnchor(anchor *anchorinfo.AnchorInfo) error {
	logger.Debugf("observing anchor - hashlink [%s], local hashlink [%s], attributedTo [%s]",
		anchor.Hashlink, anchor.Hashlink, anchor.AttributedTo)

	startTime := time.Now()

	defer func() {
		o.Metrics.ProcessAnchorTime(time.Since(startTime))
	}()

	anchorLinkset, err := o.AnchorGraph.Read(anchor.Hashlink)
	if err != nil {
		logger.Warnf("Failed to get anchor Linkset [%s] from anchor graph: %s", anchor.Hashlink, err.Error())

		return err
	}

	logger.Debugf("successfully read anchor Linkset [%s] from anchor graph", anchor.Hashlink)

	for _, anchorLink := range anchorLinkset.Linkset {
		if err := o.processAnchor(anchor, anchorLink); err != nil {
			logger.Warnf(err.Error())

			return err
		}
	}

	return nil
}

func (o *Observer) processDID(did string) error {
	logger.Debugf("processing out-of-system did[%s]", did)

	startTime := time.Now()

	defer func() {
		o.Metrics.ProcessDIDTime(time.Since(startTime))
	}()

	cidWithHint, suffix, err := getDidParts(did)
	if err != nil {
		logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

		return err
	}

	anchors, err := o.AnchorGraph.GetDidAnchors(cidWithHint, suffix)
	if err != nil {
		logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

		return err
	}

	logger.Debugf("got %d anchors for out-of-system did[%s]", len(anchors), did)

	for _, anchor := range anchors {
		logger.Debugf("processing anchor[%s] for out-of-system did[%s]", anchor.CID, did)

		if err := o.processAnchor(
			&anchorinfo.AnchorInfo{Hashlink: anchor.CID},
			anchor.Info, suffix); err != nil {
			if errors.IsTransient(err) {
				// Return an error so that the message is redelivered and retried.
				return fmt.Errorf("process out-of-system anchor [%s]: %w", anchor.CID, err)
			}

			logger.Warnf("ignoring anchor[%s] for did[%s]", anchor.CID, did, err.Error())

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

//nolint:funlen,gocyclo,cyclop
func (o *Observer) processAnchor(anchor *anchorinfo.AnchorInfo,
	anchorLink *linkset.Link, suffixes ...string) error {
	logger.Debugf("processing anchor[%s] from [%s], suffixes: %s", anchor.Hashlink, anchor.AttributedTo, suffixes)

	anchorPayload, err := anchorlinkset.GetPayloadFromAnchorLink(anchorLink)
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

	logger.Debugf("processing anchor[%s], core index[%s]", anchor.Hashlink, anchorPayload.CoreIndex)

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
			logger.Infof("Ignoring anchor event %s since it has already been processed",
				anchor.Hashlink)

			return nil
		}

		logger.Infof("No operations were processed for anchor event %s (probably because all operations in the "+
			"anchor were already processed from a duplicate anchor event) but the anchor event is missing "+
			"from storage. The anchor event will be processed (again) which may result in some duplicate key warnings "+
			"from the DB, but this shouldn't be a problem since those duplicates will be ignored.", anchor.Hashlink)
	}

	// update global did/anchor references
	acSuffixes, areNewSuffixes := getSuffixes(anchorPayload.PreviousAnchors)

	err = o.DidAnchors.PutBulk(acSuffixes, areNewSuffixes, anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("failed updating did anchor references for anchor credential[%s]: %w", anchor.Hashlink, err)
	}

	logger.Infof("Successfully processed %d DIDs in anchor[%s], core index[%s]",
		anchorPayload.OperationCount, anchor.Hashlink, anchorPayload.CoreIndex)

	// Post a 'Like' activity to the originator of the anchor credential.
	err = o.saveAnchorLinkAndPostLikeActivity(anchor)
	if err != nil {
		// This is not a critical error. We have already processed the anchor, so we don't want
		// to trigger a retry by returning a transient error. Just log a warning.
		logger.Warnf("A 'Like' activity could not be posted to the outbox: %s", err)
	}

	return nil
}

func (o *Observer) setupProofMonitoring(vc *verifiable.Credential) {
	expiryTime := time.Now().Add(o.monitoringSvcExpiry)

	// This code was moved from proof/credential handler to observer to make sure that monitoring is checked at all times
	// not just during anchor creation/publishing
	for _, proof := range getUniqueDomainCreated(vc.Proofs) {
		// getUniqueDomainCreated already checked that data is a string
		domain := proof["domain"].(string)   // nolint: errcheck, forcetypeassert
		created := proof["created"].(string) // nolint: errcheck, forcetypeassert

		createdTime, err := time.Parse(time.RFC3339, created)
		if err != nil {
			logger.Errorf("failed to setup monitoring for anchor credential[%s] proof domain[%s]: "+
				"parse created error: %s", vc.ID, domain, err.Error())

			continue
		}

		err = o.MonitoringSvc.Watch(vc, expiryTime, domain, createdTime)
		if err != nil {
			// This shouldn't be a fatal error since the anchor being processed may have multiple
			// witness proofs and, if one of the witness domains is down, it should not prevent the
			// anchor from being processed.
			logger.Errorf("failed to setup monitoring for anchor credential[%s] proof domain[%s]: %s",
				vc.ID, domain, err.Error())
		} else {
			logger.Debugf("successfully setup monitoring for anchor credential[%s] proof domain[%s]", vc.ID, domain)
		}
	}
}

func (o *Observer) saveAnchorLinkAndPostLikeActivity(anchor *anchorinfo.AnchorInfo) error {
	refURL, err := url.Parse(anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("parse hash link [%s]: %w", anchor.Hashlink, err)
	}

	err = o.saveAnchorHashlink(refURL)
	if err != nil {
		// Not fatal.
		logger.Warnf("Error saving anchor link [%s]: %s", refURL, err)
	}

	if anchor.AttributedTo == "" {
		logger.Debugf("Not posting 'Like' activity since no attributedTo ID was specified for anchor [%s]",
			anchor.Hashlink)

		return nil
	}

	attributedTo, err := url.Parse(anchor.AttributedTo)
	if err != nil {
		return fmt.Errorf("parse origin [%s]: %w", anchor.AttributedTo, err)
	}

	result, err := newLikeResult(anchor.LocalHashlink)
	if err != nil {
		return fmt.Errorf("new like result for local hashlink: %w", err)
	}

	logger.Debugf("Posting a 'Like' to the actor attributed to this activity [%s]", attributedTo)

	to := []*url.URL{attributedTo}

	// Also post a 'Like' to the creator of the anchor credential (if it's not the same as the actor above).
	originActor, err := o.resolveActorFromHashlink(refURL.String())
	if err != nil {
		return fmt.Errorf("resolve origin actor for hashlink [%s]: %w", refURL, err)
	}

	if anchor.AttributedTo != originActor.String() && originActor.String() != o.serviceIRI.String() {
		logger.Debugf("Also posting a 'Like' to the origin of this activity [%s] which was attributed to [%s]",
			originActor, anchor.AttributedTo)

		to = append(to, originActor)
	}

	err = o.doPostLikeActivity(to, refURL, result)
	if err != nil {
		return fmt.Errorf("post 'Like' activity to outbox for hashlink [%s]: %w", refURL, err)
	}

	return nil
}

func (o *Observer) doPostLikeActivity(to []*url.URL, refURL *url.URL, result *vocab.ObjectProperty) error {
	publishedTime := time.Now()

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(
			vocab.NewAnchorEvent(nil, vocab.WithURL(refURL)),
		)),
		vocab.WithTo(append(to, vocab.PublicIRI)...),
		vocab.WithPublishedTime(&publishedTime),
		vocab.WithResult(result),
	)

	if _, err := o.Outbox().Post(like); err != nil {
		return fmt.Errorf("post like: %w", err)
	}

	logger.Debugf("Posted a 'Like' activity to [%s] for hashlink [%s]", to, refURL)

	return nil
}

func (o *Observer) resolveActorFromHashlink(hl string) (*url.URL, error) {
	anchorLinksetBytes, _, err := o.CASResolver.Resolve(nil, hl, nil)
	if err != nil {
		return nil, fmt.Errorf("resolve anchor: %w", err)
	}

	logger.Debugf("Retrieved anchor from [%s]: %s", hl, anchorLinksetBytes)

	anchorLinkset := &linkset.Linkset{}

	err = json.Unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor Linkset for [%s]: %w", hl, err)
	}

	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return nil, fmt.Errorf("empty anchor Linkset [%s]", hl)
	}

	hml, err := o.WebFingerResolver.ResolveHostMetaLink(anchorLink.Author().String(),
		discoveryrest.ActivityJSONType)
	if err != nil {
		return nil, fmt.Errorf("resolve host meta-link for [%s]: %w", anchorLink.Author(), err)
	}

	actor, err := url.Parse(hml)
	if err != nil {
		return nil, fmt.Errorf(`parse URL [%s]: %w`, hml, err)
	}

	return actor, nil
}

// saveAnchorHashlink saves the hashlink of an anchor credential so that it may be returned
// in a WebFinger query as an alternate link.
func (o *Observer) saveAnchorHashlink(ref *url.URL) error {
	err := o.AnchorLinkStore.PutLinks([]*url.URL{ref})
	if err != nil {
		return fmt.Errorf("put anchor link [%s]: %w", ref, err)
	}

	logger.Debugf("Saved anchor link [%s]", ref)

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
		return nil, nil
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
