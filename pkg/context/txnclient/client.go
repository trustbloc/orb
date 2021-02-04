/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnclient

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/api/txn"
	"github.com/trustbloc/orb/pkg/didtxnref"
)

// Client implements writing orb transactions.
type Client struct {
	*Providers
	namespace string
	txnCh     chan []string
}

// Providers contains all of the providers required by the client.
type Providers struct {
	TxnGraph  txnGraph
	DidTxns   didTxns
	TxnSigner txnSigner
}

type txnGraph interface {
	Add(txn *verifiable.Credential) (string, error)
}

type txnSigner interface {
	Sign(vc *verifiable.Credential) (*verifiable.Credential, error)
}

type didTxns interface {
	Add(did, cid string) error
	Get(did string) ([]string, error)
}

// New returns a new orb transaction client.
func New(namespace string, providers *Providers, txnCh chan []string) *Client {
	return &Client{
		Providers: providers,
		txnCh:     txnCh,
		namespace: namespace,
	}
}

// WriteAnchor writes anchor string to orb transaction.
func (c *Client) WriteAnchor(anchor string, refs []*operation.Reference, version uint64) error {
	vc, err := c.buildCredential(anchor, refs, version)
	if err != nil {
		return err
	}

	// TODO: create an offer for witnesses and wait for witness proofs (separate go routine)

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
func (c *Client) Read(_ int) (bool, *txnapi.SidetreeTxn) {
	// not used
	return false, nil
}

//
func (c *Client) getPreviousTransactions(refs []*operation.Reference) (map[string]string, error) {
	// assemble map of previous did transaction for each did that is referenced in anchor
	previousDidTxns := make(map[string]string)

	for _, ref := range refs {
		txns, err := c.DidTxns.Get(ref.UniqueSuffix)
		if err != nil && err != didtxnref.ErrDidTransactionReferencesNotFound {
			return nil, err
		}

		// TODO: it is ok for transaction references not to be there for create; handle other types here

		// get did's last transaction
		if len(txns) > 0 {
			previousDidTxns[ref.UniqueSuffix] = txns[len(txns)-1]
		}
	}

	return previousDidTxns, nil
}

// WriteAnchor writes anchor string to orb transaction.
func (c *Client) buildCredential(anchor string, refs []*operation.Reference, version uint64) (*verifiable.Credential, error) { //nolint: lll
	const defVCContext = "https://www.w3.org/2018/credentials/v1"
	// TODO: Add context for anchor credential and define credential subject attributes there

	// get previous did transaction for each did that is referenced in anchor
	previousTxns, err := c.getPreviousTransactions(refs)
	if err != nil {
		return nil, err
	}

	subject := txn.Payload{
		AnchorString:         anchor,
		Namespace:            c.namespace,
		Version:              version,
		PreviousTransactions: previousTxns,
	}

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential", "AnchorCredential"},
		Context: []string{defVCContext},
		Subject: subject,
		Issuer: verifiable.Issuer{
			ID: "http://peer1.com", // TODO: Configure this with signature PR
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	// TODO: Sign VC here

	return vc, nil
}
