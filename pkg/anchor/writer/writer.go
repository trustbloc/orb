/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/didanchorref"
)

var logger = log.New("anchor-writer")

// Writer implements writing anchors.
type Writer struct {
	*Providers
	namespace string
	vcCh      <-chan *verifiable.Credential
	anchorCh  chan []string
}

// Providers contains all of the providers required by the client.
type Providers struct {
	AnchorGraph   anchorGraph
	DidAnchors    didAnchors
	AnchorBuilder anchorBuilder
	ProofHandler  proofHandler
	Store         vcStore
	OpProcessor   opProcessor
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
	Add(dids []string, cid string) error
	Last(did string) (string, error)
}

type vcStore interface {
	Put(vc *verifiable.Credential) error
	Get(id string) (*verifiable.Credential, error)
}

type proofHandler interface {
	RequestProofs(vc *verifiable.Credential, witnesses []string) error
}

// New returns a new anchor writer.
func New(namespace string, providers *Providers, anchorCh chan []string, vcCh chan *verifiable.Credential) *Writer {
	w := &Writer{
		Providers: providers,
		anchorCh:  anchorCh,
		vcCh:      vcCh,
		namespace: namespace,
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
		return fmt.Errorf("failed to store anchor credential: %s", err.Error())
	}

	logger.Debugf("stored anchor credential[%s] for anchor: %s", vc.ID, anchor)

	// figure out witness list for this anchor file
	witnesses, err := c.getWitnesses(refs)
	if err != nil {
		return fmt.Errorf("failed to create witness list: %s", err.Error())
	}

	// request proofs from witnesses
	err = c.ProofHandler.RequestProofs(vc, witnesses)
	if err != nil {
		return fmt.Errorf("failed to request proofs from witnesses: %s", err.Error())
	}

	return nil
}

// Read reads transactions since transaction time.
// TODO: This is not used and can be removed from interface if we change observer in sidetree-mock to point
// to core observer (can be done easily) Concern: Reference app has this interface.
func (c *Writer) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}

//
func (c *Writer) getPreviousAnchors(refs []*operation.Reference) (map[string]string, error) {
	// assemble map of previous did anchors for each did that is referenced in anchor
	previousAnchors := make(map[string]string)

	for _, ref := range refs {
		last, err := c.DidAnchors.Last(ref.UniqueSuffix)
		if err != nil {
			if err == didanchorref.ErrDidAnchorsNotFound {
				if ref.Type != operation.TypeCreate {
					return nil, fmt.Errorf("previous did anchor reference not found for %s operation for did[%s]", ref.Type, ref.UniqueSuffix) //nolint:lll
				}

				// create doesn't have previous anchor references
				previousAnchors[ref.UniqueSuffix] = ""

				continue
			} else {
				return nil, err
			}
		}

		previousAnchors[ref.UniqueSuffix] = last
	}

	return previousAnchors, nil
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
		return nil, fmt.Errorf("failed to build anchor credential: %s", err.Error())
	}

	return vc, nil
}

func (c *Writer) listenForWitnessedAnchorCredentials() {
	logger.Debugf("starting witnessed anchored credentials listener")

	for vc := range c.vcCh {
		logger.Debugf("got witnessed anchor credential: %s: %s", vc.ID)

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

	err = c.DidAnchors.Add(suffixes, cid)
	if err != nil {
		logger.Errorf("failed updating did anchor references for anchor credential[%s]: %s", vc.ID, err.Error())

		return
	}

	// TODO: announce anchor to followers and node observer (if running in observer node)

	c.anchorCh <- []string{cid}
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
