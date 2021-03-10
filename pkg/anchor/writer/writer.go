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
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/anchor/txn"
	"github.com/trustbloc/orb/pkg/didtxnref"
)

var logger = log.New("txn-client")

// Writer implements writing orb transactions.
type Writer struct {
	*Providers
	namespace string
	txnCh     chan []string
}

// Providers contains all of the providers required by the client.
type Providers struct {
	TxnGraph   txnGraph
	DidTxns    didTxns
	TxnBuilder txnBuilder
	Store      vcStore
}

type txnGraph interface {
	Add(txn *verifiable.Credential) (string, error)
}

type txnBuilder interface {
	Build(subject *txn.Payload) (*verifiable.Credential, error)
}

type didTxns interface {
	Add(did, cid string) error
	Last(did string) (string, error)
}

type vcStore interface {
	Put(vc *verifiable.Credential) error
	Get(id string) (*verifiable.Credential, error)
}

// New returns a new orb transaction client.
func New(namespace string, providers *Providers, txnCh chan []string) *Writer {
	return &Writer{
		Providers: providers,
		txnCh:     txnCh,
		namespace: namespace,
	}
}

// WriteAnchor writes anchor string to orb transaction.
func (c *Writer) WriteAnchor(anchor string, refs []*operation.Reference, version uint64) error {
	// build anchor credential signed by orb server (org)
	vc, err := c.buildCredential(anchor, refs, version)
	if err != nil {
		return err
	}

	logger.Debugf("created anchor credential for anchor: %s", anchor)

	// store anchor credential
	err = c.Store.Put(vc)
	if err != nil {
		return err
	}

	// TODO: create an offer for witnesses and wait for witness proofs

	// TODO: Add proofs to stored anchor credential

	cid, err := c.TxnGraph.Add(vc)
	if err != nil {
		return err
	}

	// update global did/txn references
	for _, ref := range refs {
		addErr := c.DidTxns.Add(ref.UniqueSuffix, cid)
		if addErr != nil {
			return addErr
		}
	}

	// TODO: announce txn to followers and node observer (if running in observer node)

	c.txnCh <- []string{cid}

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
func (c *Writer) getPreviousTransactions(refs []*operation.Reference) (map[string]string, error) {
	// assemble map of previous did transaction for each did that is referenced in anchor
	previousDidTxns := make(map[string]string)

	for _, ref := range refs {
		last, err := c.DidTxns.Last(ref.UniqueSuffix)
		if err != nil {
			if err == didtxnref.ErrDidTransactionsNotFound {
				// TODO: it is ok for transaction references not to be there for create; handle other types here
				continue
			} else {
				return nil, err
			}
		}

		previousDidTxns[ref.UniqueSuffix] = last
	}

	return previousDidTxns, nil
}

// WriteAnchor writes anchor string to orb transaction.
func (c *Writer) buildCredential(anchor string, refs []*operation.Reference, version uint64) (*verifiable.Credential, error) { //nolint: lll
	// get previous did transaction for each did that is referenced in anchor
	previousTxns, err := c.getPreviousTransactions(refs)
	if err != nil {
		return nil, err
	}

	subject := &txn.Payload{
		AnchorString:         anchor,
		Namespace:            c.namespace,
		Version:              version,
		PreviousTransactions: previousTxns,
	}

	vc, err := c.TxnBuilder.Build(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to build anchor credential: %s", err.Error())
	}

	return vc, nil
}
