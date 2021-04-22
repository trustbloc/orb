/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
)

var logger = log.New("anchor-writer")

// Writer implements writing anchors.
type Writer struct {
	*Providers
	namespace    string
	vcCh         <-chan *verifiable.Credential
	anchorCh     chan []string
	apServiceIRI *url.URL
	casIRI       *url.URL
}

// Providers contains all of the providers required by the client.
type Providers struct {
	AnchorGraph   anchorGraph
	DidAnchors    didAnchors
	AnchorBuilder anchorBuilder
	Store         vcStore
	OpProcessor   opProcessor
	Outbox        outbox
}

type outbox interface {
	Post(activity *vocab.ActivityType) (*url.URL, error)
}

type opProcessor interface {
	Resolve(uniqueSuffix string) (*protocol.ResolutionModel, error)
}

type anchorGraph interface {
	Add(anchor *verifiable.Credential) (string, error)
}

type anchorBuilder interface {
	Build(subject *subject.Payload) (*verifiable.Credential, error)
}

type didAnchors interface {
	Put(dids []string, cid string) error
	Get(did []string) ([]string, error)
}

type vcStore interface {
	Put(vc *verifiable.Credential) error
	Get(id string) (*verifiable.Credential, error)
}

// New returns a new anchor writer.
func New(namespace string, apServiceIRI, casURL *url.URL, providers *Providers,
	anchorCh chan []string, vcCh chan *verifiable.Credential) *Writer {
	w := &Writer{
		Providers:    providers,
		anchorCh:     anchorCh,
		vcCh:         vcCh,
		namespace:    namespace,
		apServiceIRI: apServiceIRI,
		casIRI:       casURL,
	}

	go w.listenForWitnessedAnchorCredentials()

	return w
}

// WriteAnchor writes Sidetree anchor string to Orb anchor.
func (c *Writer) WriteAnchor(anchor string, refs []*operation.Reference, version uint64) error {
	// build anchor credential signed by orb server (org)
	vc, err := c.buildCredential(anchor, refs, version)
	if err != nil {
		return err
	}

	// store anchor credential
	err = c.Store.Put(vc)
	if err != nil {
		return fmt.Errorf("failed to store anchor credential: %w", err)
	}

	logger.Debugf("stored anchor credential[%s] for anchor: %s", vc.ID, anchor)

	// figure out witness list for this anchor file
	witnesses, err := c.getWitnesses(refs)
	if err != nil {
		return fmt.Errorf("failed to create witness list: %w", err)
	}

	// send an offer activity to witnesses (request witnessing anchor credential)
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

	anchors, err := c.DidAnchors.Get(suffixes)
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
		return nil, err // nolint: wrapcheck
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

func (c *Writer) listenForWitnessedAnchorCredentials() {
	logger.Debugf("starting witnessed anchored credentials listener")

	for vc := range c.vcCh {
		logger.Debugf("got witnessed anchor credential: %s", vc.ID)

		c.handle(vc)
	}

	logger.Debugf("[%s] witnessed anchor credential listener stopped")
}

func (c *Writer) handle(vc *verifiable.Credential) {
	logger.Debugf("handling witnessed anchored credential: %s", vc.ID)

	// store anchor credential with witness proofs
	err := c.Store.Put(vc)
	if err != nil {
		logger.Warnf("failed to store witnessed anchor credential[%s]: %s", vc.ID, err.Error())

		// TODO: How to handle recovery after this and all other errors in this handler

		return
	}

	cid, err := c.AnchorGraph.Add(vc)
	if err != nil {
		logger.Errorf("failed to add witnessed anchor credential[%s] to anchor graph: %s", vc.ID, err.Error())

		return
	}

	anchorSubject, err := util.GetAnchorSubject(vc)
	if err != nil {
		logger.Errorf("failed to extract txn payload from witnessed anchor credential[%s]: %s", vc.ID, err.Error())

		return
	}

	// update global did/anchor references
	suffixes := getKeys(anchorSubject.PreviousAnchors)

	err = c.DidAnchors.Put(suffixes, cid)
	if err != nil {
		logger.Errorf("failed updating did anchor references for anchor credential[%s]: %s", vc.ID, err.Error())

		return
	}

	c.anchorCh <- []string{cid}

	logger.Debugf("posted cid[%s] to anchor channel", cid)

	// announce anchor credential activity to followers
	err = c.postCreateActivity(vc, cid)
	if err != nil {
		logger.Warnf("failed to post new create activity for cid[%s]: %s", cid, err.Error())

		return
	}
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
		vocab.WithTo(systemFollowers),
	)

	postID, err := c.Outbox.Post(create)
	if err != nil {
		return err // nolint: wrapcheck
	}

	logger.Debugf("created activity for cid[%s], post id[%s]", cid, postID)

	return nil
}

// postOfferActivity creates and posts offer activity (requests witnessing of anchor credential).
func (c *Writer) postOfferActivity(vc *verifiable.Credential, witnesses []string) error {
	logger.Debugf("sending anchor credential[%s] to system witnesses plus: %s", vc.ID, witnesses)

	witnessesIRI, err := c.getWitnessesIRI(witnesses)
	if err != nil {
		return err
	}

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal anchor credential: %w", err)
	}

	obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return fmt.Errorf("failed to create new object with document: %w", err)
	}

	startTime := time.Now()

	// TODO: configure
	endTime := startTime.Add(time.Hour)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithTo(witnessesIRI...),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
	)

	postID, err := c.Outbox.Post(offer)
	if err != nil {
		return err // nolint: wrapcheck
	}

	logger.Debugf("created pre-announce activity for vc[%s], post id[%s]", vc.ID, postID)

	return nil
}

func (c *Writer) getWitnessesIRI(witnesses []string) ([]*url.URL, error) {
	var allWitnesses []*url.URL

	for _, w := range witnesses {
		witnessIRI, err := url.Parse(w)
		if err != nil {
			return nil, fmt.Errorf("failed to parse witness path[%s]: %w", w, err)
		}

		allWitnesses = append(allWitnesses, witnessIRI)
	}

	// get system witness IRI
	systemWitnesses, err := url.Parse(c.apServiceIRI.String() + resthandler.WitnessesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse system witness path: %w", err)
	}

	// add system witnesses (activity pub collection) to the list of witnesses
	allWitnesses = append(allWitnesses, systemWitnesses)

	return allWitnesses, nil
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
				return nil, err // nolint: wrapcheck
			}

			anchorOriginObj = result.AnchorOrigin
		default:
			return nil, fmt.Errorf("operation type '%s' not supported for assembling witness list", ref.Type)
		}

		// TODO: string or array of strings?
		anchorOrigin, ok := anchorOriginObj.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected interface '%T' for anchor origin", anchorOriginObj)
		}

		_, ok = uniqueWitnesses[anchorOrigin]
		if !ok {
			witnesses = append(witnesses, anchorOrigin)
			uniqueWitnesses[anchorOrigin] = true
		}
	}

	return witnesses, nil
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

// Read reads transactions since transaction time.
// TODO: This is not used and can be removed from interface if we change observer in sidetree-mock to point
// to core observer (can be done easily) Concern: Reference app has this interface.
func (c *Writer) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}
