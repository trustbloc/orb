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
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("orb-observer")

const defaultSubscriberPoolSize = 5

// AnchorGraph interface to access anchors.
type AnchorGraph interface {
	Read(hl string) (*vocab.AnchorEventType, error)
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
	PutBulk(dids []string, cid string) error
}

// Publisher publishes anchors and DIDs to a message queue for processing.
type Publisher interface {
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
	PublishDID(did string) error
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
	Post(activity *vocab.ActivityType) (*url.URL, error)
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
}

type outboxProvider func() Outbox

type options struct {
	discoveryDomain    string
	subscriberPoolSize uint
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
func WithSubscriberPoolSize(value uint) Option {
	return func(opts *options) {
		opts.subscriberPoolSize = value
	}
}

// Providers contains all of the providers required by the TxnProcessor.
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
	AnchorLinkStore   anchorLinkStore
}

// Observer receives transactions over a channel and processes them by storing them to an operation store.
type Observer struct {
	*Providers

	serviceIRI      *url.URL
	pubSub          *PubSub
	discoveryDomain string
}

// New returns a new observer.
func New(serviceIRI *url.URL, providers *Providers, opts ...Option) (*Observer, error) {
	optns := &options{}

	for _, opt := range opts {
		opt(optns)
	}

	o := &Observer{
		serviceIRI:      serviceIRI,
		Providers:       providers,
		discoveryDomain: optns.discoveryDomain,
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

	anchorEvent, err := o.AnchorGraph.Read(anchor.Hashlink)
	if err != nil {
		logger.Warnf("Failed to get anchor event[%s] node from anchor graph: %s", anchor.Hashlink, err.Error())

		return err
	}

	logger.Debugf("successfully read anchor event[%s] from anchor graph", anchor.Hashlink)

	if err := o.processAnchor(anchor, anchorEvent); err != nil {
		logger.Warnf(err.Error())

		return err
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

//nolint:funlen
func (o *Observer) processAnchor(anchor *anchorinfo.AnchorInfo,
	anchorEvent *vocab.AnchorEventType, suffixes ...string) error {
	logger.Debugf("processing anchor[%s] from [%s], suffixes: %s", anchor.Hashlink, anchor.AttributedTo, suffixes)

	anchorPayload, err := anchorevent.GetPayloadFromAnchorEvent(anchorEvent)
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

	vc, err := util.VerifiableCredentialFromAnchorEvent(anchorEvent,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(o.DocLoader),
	)
	if err != nil {
		return fmt.Errorf("get verifiable credential from anchor event: %w", err)
	}

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:      uint64(vc.Issued.Unix()),
		AnchorString:         ad.GetAnchorString(),
		Namespace:            anchorPayload.Namespace,
		ProtocolVersion:      anchorPayload.Version,
		CanonicalReference:   canonicalID,
		EquivalentReferences: equivalentRefs,
	}

	logger.Debugf("processing anchor[%s], core index[%s]", anchor.Hashlink, anchorPayload.CoreIndex)

	err = v.TransactionProcessor().Process(sidetreeTxn, suffixes...)
	if err != nil {
		return fmt.Errorf("failed to process anchor[%s] core index[%s]: %w",
			anchor.Hashlink, anchorPayload.CoreIndex, err)
	}

	// update global did/anchor references
	acSuffixes := getSuffixes(anchorPayload.PreviousAnchors)

	err = o.DidAnchors.PutBulk(acSuffixes, anchor.Hashlink)
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

func (o *Observer) saveAnchorLinkAndPostLikeActivity(anchor *anchorinfo.AnchorInfo) error {
	if anchor.AttributedTo == "" {
		logger.Debugf("Not posting 'Like' activity since no attributedTo ID was specified for anchor [%s]",
			anchor.Hashlink)

		return nil
	}

	refURL, err := url.Parse(anchor.Hashlink)
	if err != nil {
		return fmt.Errorf("parse hash link [%s]: %w", anchor.Hashlink, err)
	}

	attributedTo, err := url.Parse(anchor.AttributedTo)
	if err != nil {
		return fmt.Errorf("parse origin [%s]: %w", anchor.AttributedTo, err)
	}

	err = o.saveAnchorHashlink(refURL)
	if err != nil {
		// Not fatal.
		logger.Warnf("Error saving anchor link [%s]: %s", refURL, err)
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
			vocab.NewAnchorEvent(vocab.WithURL(refURL)),
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
	anchorEventBytes, _, err := o.CASResolver.Resolve(nil, hl, nil)
	if err != nil {
		return nil, fmt.Errorf("resolve anchor event: %w", err)
	}

	logger.Debugf("Retrieved anchor event from [%s]: %s", hl, anchorEventBytes)

	anchorEvent := &vocab.AnchorEventType{}

	err = json.Unmarshal(anchorEventBytes, anchorEvent)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor event for [%s]: %w", hl, err)
	}

	hml, err := o.WebFingerResolver.ResolveHostMetaLink(anchorEvent.AttributedTo().String(),
		discoveryrest.ActivityJSONType)
	if err != nil {
		return nil, fmt.Errorf("resolve host meta-link for [%s]: %w", anchorEvent.AttributedTo(), err)
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

func getSuffixes(m []*subject.SuffixAnchor) []string {
	suffixes := make([]string, 0, len(m))
	for _, k := range m {
		suffixes = append(suffixes, k.Suffix)
	}

	return suffixes
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
		vocab.NewAnchorEvent(vocab.WithURL(u))),
	), nil
}
