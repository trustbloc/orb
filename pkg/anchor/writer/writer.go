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
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/anchor/vcpubsub"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/errors"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

var logger = log.New("anchor-writer")

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
}

// Providers contains all of the providers required by the client.
type Providers struct {
	AnchorGraph   anchorGraph
	DidAnchors    didAnchors
	AnchorBuilder anchorBuilder
	VCStore       vcStore
	VCStatusStore vcStatusStore
	OpProcessor   opProcessor
	Outbox        outbox
	Witness       witness
	Signer        signer
	MonitoringSvc monitoringSvc
	WitnessStore  witnessStore
	ActivityStore activityStore
}

type activityStore interface {
	QueryReferences(refType spi.ReferenceType, query *spi.Criteria, opts ...spi.QueryOpt) (spi.ReferenceIterator, error)
}

type witnessStore interface {
	Put(vcID string, witnesses []*proof.WitnessProof) error
	Delete(vcID string) error
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
	Post(activity *vocab.ActivityType) (*url.URL, error)
}

type opProcessor interface {
	Resolve(uniqueSuffix string) (*protocol.ResolutionModel, error)
}

type anchorGraph interface {
	Add(anchor *verifiable.Credential) (string, string, error)
}

type anchorBuilder interface {
	Build(subject *subject.Payload) (*verifiable.Credential, error)
}

type didAnchors interface {
	GetBulk(did []string) ([]string, error)
}

type vcStore interface {
	Put(vc *verifiable.Credential) error
	Get(id string) (*verifiable.Credential, error)
}

type vcStatusStore interface {
	AddStatus(vcID string, status proof.VCStatus) error
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
	documentLoader ld.DocumentLoader, resourceResolver *resourceresolver.Resolver) (*Writer, error) {
	w := &Writer{
		Providers:            providers,
		anchorPublisher:      anchorPublisher,
		namespace:            namespace,
		apServiceIRI:         apServiceIRI,
		casIRI:               casURL,
		maxWitnessDelay:      maxWitnessDelay,
		signWithLocalWitness: signWithLocalWitness,
		resourceResolver:     resourceResolver,
	}

	s, err := vcpubsub.NewSubscriber(pubSub, w.handle, documentLoader)
	if err != nil {
		return nil, fmt.Errorf("new subscriber: %w", err)
	}

	s.Start()

	return w, nil
}

// WriteAnchor writes Sidetree anchor string to Orb anchor.
func (c *Writer) WriteAnchor(anchor string, refs []*operation.Reference, version uint64) error {
	// build anchor credential
	vc, err := c.buildCredential(anchor, refs, version)
	if err != nil {
		return err
	}

	// figure out witness list for this anchor file
	witnesses, err := c.getWitnesses(refs)
	if err != nil {
		return fmt.Errorf("failed to create witness list: %w", err)
	}

	// sign credential using local witness log or server public key
	vc, err = c.signCredential(vc, witnesses)
	if err != nil {
		return err
	}

	logger.Debugf("signed and stored anchor credential[%s] for anchor: %s", vc.ID, anchor)

	// send an offer activity to witnesses (request witnessing anchor credential from non-local witness logs)
	err = c.postOfferActivity(vc, witnesses)
	if err != nil {
		return fmt.Errorf("failed to post new offer activity for vc[%s]: %w", vc.ID, err)
	}

	return nil
}

func (c *Writer) getPreviousAnchors(refs []*operation.Reference) (map[string]string, error) {
	// assemble map of latest did anchor references
	previousAnchors := make(map[string]string)

	suffixes := getSuffixes(refs)

	anchors, err := c.DidAnchors.GetBulk(suffixes)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve latest did anchor references for suffixes[%s]", suffixes)
	}

	for i, ref := range refs {
		if anchors[i] == "" {
			if ref.Type != operation.TypeCreate {
				return nil, fmt.Errorf("previous did anchor reference not found for %s operation for did[%s]", ref.Type, ref.UniqueSuffix) //nolint:lll
			}

			// create doesn't have previous anchor references
			previousAnchors[ref.UniqueSuffix] = ""
		} else {
			previousAnchors[ref.UniqueSuffix] = anchors[i]
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
func (c *Writer) buildCredential(anchor string, refs []*operation.Reference, version uint64) (*verifiable.Credential, error) { //nolint: lll
	// get previous anchors for each did that is referenced in this anchor
	previousAnchors, err := c.getPreviousAnchors(refs)
	if err != nil {
		return nil, err
	}

	ad, err := util.ParseAnchorString(anchor)
	if err != nil {
		return nil, err
	}

	payload := &subject.Payload{
		OperationCount:  ad.OperationCount,
		CoreIndex:       ad.CoreIndexFileURI,
		Namespace:       c.namespace,
		Version:         version,
		PreviousAnchors: previousAnchors,
	}

	vc, err := c.AnchorBuilder.Build(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build anchor credential: %w", err)
	}

	return vc, nil
}

func (c *Writer) signCredential(vc *verifiable.Credential, witnesses []string) (*verifiable.Credential, error) {
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
	signedVC, err := c.Signer.Sign(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign anchor credential[%s]: %w", vc.ID, err)
	}

	// store anchor credential
	err = c.VCStore.Put(signedVC)
	if err != nil {
		return nil, fmt.Errorf("failed to store anchor credential: %w", err)
	}

	return signedVC, nil
}

func (c *Writer) signCredentialWithLocalWitnessLog(vc *verifiable.Credential) (*verifiable.Credential, error) {
	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal anchor credential[%s] for local witness: %w", vc.ID, err)
	}

	// send anchor credential to local witness log
	proofBytes, err := c.Witness.Witness(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("local witnessing failed for anchor credential[%s]: %w", vc.ID, err)
	}

	var witnessProof vct.Proof

	err = json.Unmarshal(proofBytes, &witnessProof)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal local witness proof for anchor credential[%s]: %w", vc.ID, err)
	}

	// TODO: need to review this logic, monitoring does not use it
	// store anchor credential (required for monitoring)
	err = c.VCStore.Put(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to store localy witnessed anchor credential: %w", err)
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

	err = c.MonitoringSvc.Watch(vc, time.Now().Add(c.maxWitnessDelay), domain, createdTime)
	if err != nil {
		return nil, fmt.Errorf("failed to setup monitoring for local witness for anchor credential[%s]: %w", vc.ID, err)
	}

	return vc, nil
}

func (c *Writer) handle(vc *verifiable.Credential) error {
	logger.Debugf("handling witnessed anchored credential: %s", vc.ID)

	// store anchor credential with witness proofs
	err := c.VCStore.Put(vc)
	if err != nil {
		logger.Warnf("failed to store witnessed anchor credential[%s]: %s", vc.ID, err.Error())

		return errors.NewTransient(fmt.Errorf("store witnessed anchor credential[%s]: %w", vc.ID, err))
	}

	cid, hint, err := c.AnchorGraph.Add(vc)
	if err != nil {
		logger.Errorf("failed to add witnessed anchor credential[%s] to anchor graph: %s", vc.ID, err.Error())

		return fmt.Errorf("add witnessed anchor credential[%s] to anchor graph: %w", vc.ID, err)
	}

	fullWebCASURL, err := url.Parse(fmt.Sprintf("%s/%s", c.casIRI.String(), cid))
	if err != nil {
		logger.Errorf("failed to construct full WebCAS URL from the following two parts: [%s] and [%s]",
			c.casIRI.String(), cid)

		return fmt.Errorf("construct full WebCAS URL from the following two parts: [%s] and [%s]: %w",
			c.casIRI.String(), cid, err)
	}

	err = c.anchorPublisher.PublishAnchor(&anchorinfo.AnchorInfo{CID: cid, WebCASURL: fullWebCASURL, Hint: hint})
	if err != nil {
		logger.Warnf("failed to publish anchors for cid[%s]: %s", cid, err.Error())

		return fmt.Errorf("publish anchors for cid[%s]: %w", vc.ID, err)
	}

	logger.Debugf("posted cid[%s] to anchor channel", cid)

	// announce anchor credential activity to followers
	err = c.postCreateActivity(vc, cid)
	if err != nil {
		logger.Warnf("failed to post new create activity for cid[%s]: %s", cid, err.Error())

		// Don't return a transient error since the anchor has already been published and we don't want to trigger a retry.
		return fmt.Errorf("post create activity for cid[%s]: %w", cid, err)
	}

	err = c.WitnessStore.Delete(vc.ID)
	if err != nil {
		// this is a clean-up task so no harm if there was an error
		logger.Warnf("failed to delete witnesses for vc[%s]: %s", vc.ID, err.Error())
	}

	return nil
}

// postCreateActivity creates and posts create activity (announces anchor credential to followers).
func (c *Writer) postCreateActivity(vc *verifiable.Credential, cid string) error { //nolint: interfacer
	cidURL, err := url.Parse(fmt.Sprintf("%s/%s", c.casIRI.String(), cid))
	if err != nil {
		return fmt.Errorf("failed to parse cid URL: %w", err)
	}

	targetProperty := vocab.NewObjectProperty(vocab.WithObject(
		vocab.NewObject(
			vocab.WithID(cidURL),
			vocab.WithCID(cid),
			vocab.WithType(vocab.TypeContentAddressedStorage),
		),
	))

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal anchor credential: %w", err)
	}

	obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	systemFollowers, err := url.Parse(c.apServiceIRI.String() + resthandler.FollowersPath)
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	create := vocab.NewCreateActivity(
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithTarget(targetProperty),
		vocab.WithContext(vocab.ContextOrb),
		vocab.WithTo(systemFollowers, vocab.PublicIRI),
	)

	postID, err := c.Outbox.Post(create)
	if err != nil {
		return err
	}

	logger.Debugf("created activity for cid[%s], post id[%s]", cid, postID)

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Writer) postOfferActivity(vc *verifiable.Credential, witnesses []string) error {
	logger.Debugf("sending anchor credential[%s] to system witnesses plus: %s", vc.ID, witnesses)

	batchWitnessesIRI, err := c.getBatchWitnessesIRI(witnesses)
	if err != nil {
		return err
	}

	// get system witness IRI
	systemWitnessesIRI, err := url.Parse(c.apServiceIRI.String() + resthandler.WitnessesPath)
	if err != nil {
		return fmt.Errorf("failed to parse system witness path: %w", err)
	}

	var witnessesIRI []*url.URL

	// add batch witnesses and system witnesses (activity pub collection)
	witnessesIRI = append(witnessesIRI, batchWitnessesIRI...)
	witnessesIRI = append(witnessesIRI, vocab.PublicIRI, systemWitnessesIRI)

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal anchor credential: %w", err)
	}

	obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	startTime := time.Now()
	endTime := startTime.Add(c.maxWitnessDelay)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithTo(witnessesIRI...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
	)

	// store witnesses before posting offers because handlers sometimes get invoked before
	// witnesses and vc status are stored
	err = c.storeWitnesses(vc.ID, batchWitnessesIRI)
	if err != nil {
		return err
	}

	postID, err := c.Outbox.Post(offer)
	if err != nil {
		// TODO: Offers were not sent - delete vc status and witness store entries (issue-452)
		return fmt.Errorf("failed to post offer for vcID[%s]: %w", vc.ID, err)
	}

	logger.Debugf("created pre-announce activity for vc[%s], post id[%s]", vc.ID, postID)

	return nil
}

func (c *Writer) getBatchWitnessesIRI(witnesses []string) ([]*url.URL, error) {
	var witnessesIRI []*url.URL

	for _, w := range witnesses {
		// do not add local domain as external witness
		if w == c.apServiceIRI.String() {
			continue
		}

		witnessIRI, err := url.Parse(w)
		if err != nil {
			return nil, fmt.Errorf("failed to parse witness path[%s]: %w", w, err)
		}

		witnessesIRI = append(witnessesIRI, witnessIRI)
	}

	return witnessesIRI, nil
}

// getWitnesses returns the list of anchor origins for all dids in the Sidetree batch.
// Create and recover operations contain anchor origin in operation references.
// For update and deactivate operations we have to 'resolve' did in order to figure out anchor origin.
func (c *Writer) getWitnesses(refs []*operation.Reference) ([]string, error) {
	var witnesses []string

	uniqueWitnesses := make(map[string]bool)

	for _, ref := range refs {
		var anchorOriginObj interface{}

		switch ref.Type {
		case operation.TypeCreate, operation.TypeRecover:
			anchorOriginObj = ref.AnchorOrigin

		case operation.TypeUpdate, operation.TypeDeactivate:
			result, err := c.OpProcessor.Resolve(ref.UniqueSuffix)
			if err != nil {
				return nil, err
			}

			anchorOriginObj = result.AnchorOrigin
		default:
			return nil, fmt.Errorf("operation type '%s' not supported for assembling witness list", ref.Type)
		}

		anchorOrigin, ok := anchorOriginObj.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected interface '%T' for anchor origin", anchorOriginObj)
		}

		logger.Debugf("Resolving witness for the following anchor origin: %s", anchorOrigin)

		resolvedWitness, err := c.resourceResolver.Resolve(anchorOrigin, discoveryrest.WitnessType)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve witness: %w", err)
		}

		logger.Debugf("Successfully resolved witness %s from %s", resolvedWitness, anchorOrigin)

		_, ok = uniqueWitnesses[resolvedWitness]

		if !ok {
			witnesses = append(witnesses, resolvedWitness)
			uniqueWitnesses[resolvedWitness] = true
		}
	}

	return witnesses, nil
}

// Read reads transactions since transaction time.
// TODO: This is not used and can be removed from interface if we change observer in sidetree-mock to point
// to core observer (can be done easily) Concern: Reference app has this interface.
func (c *Writer) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}

func (c *Writer) storeWitnesses(vcID string, batchWitnesses []*url.URL) error {
	var witnesses []*proof.WitnessProof

	for _, w := range batchWitnesses {
		witnesses = append(witnesses,
			&proof.WitnessProof{
				Type:    proof.WitnessTypeBatch,
				Witness: w.String(),
			})
	}

	systemWitnesses, err := c.getSystemWitnesses()
	if err != nil {
		return err
	}

	for _, systemWitnessURI := range systemWitnesses {
		witnesses = append(witnesses,
			&proof.WitnessProof{
				Type:    proof.WitnessTypeSystem,
				Witness: systemWitnessURI.String(),
			})
	}

	err = c.WitnessStore.Put(vcID, witnesses)
	if err != nil {
		return fmt.Errorf("failed to store witnesses for vcID[%s]: %w", vcID, err)
	}

	err = c.VCStatusStore.AddStatus(vcID, proof.VCStatusInProcess)
	if err != nil {
		return fmt.Errorf("failed to set 'in-process' status for vcID[%s]: %w", vcID, err)
	}

	return nil
}

func (c *Writer) getSystemWitnesses() ([]*url.URL, error) {
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

	return systemWitnessesIRI, nil
}
