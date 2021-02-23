/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/anchor/util"
)

var logger = log.New("orb-observer")

// TxnProvider interface to access orb txn.
type TxnProvider interface {
	RegisterForOrbTxn() <-chan []string
}

// TxnGraph interface to access orb transactions.
type TxnGraph interface {
	Read(cid string) (*verifiable.Credential, error)
}

// OperationStore interface to access operation store.
type OperationStore interface {
	Put(ops []*operation.AnchoredOperation) error
}

// OperationFilter filters out operations before they are persisted.
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*operation.AnchoredOperation) ([]*operation.AnchoredOperation, error)
}

// Providers contains all of the providers required by the TxnProcessor.
type Providers struct {
	TxnProvider            TxnProvider
	ProtocolClientProvider protocol.ClientProvider
	TxnGraph
}

// Observer receives transactions over a channel and processes them by storing them to an operation store.
type Observer struct {
	*Providers

	stopCh chan struct{}
}

// New returns a new observer.
func New(providers *Providers) *Observer {
	return &Observer{
		Providers: providers,
		stopCh:    make(chan struct{}, 1),
	}
}

// Start starts observer routines.
func (o *Observer) Start() {
	go o.listen(o.TxnProvider.RegisterForOrbTxn())
}

// Stop stops the observer.
func (o *Observer) Stop() {
	o.stopCh <- struct{}{}
}

func (o *Observer) listen(txnsCh <-chan []string) {
	for {
		select {
		case <-o.stopCh:
			logger.Infof("The observer has been stopped. Exiting.")

			return

		case txns, ok := <-txnsCh:
			if !ok {
				logger.Warnf("Notification channel was closed. Exiting.")

				return
			}

			o.process(txns)
		}
	}
}

func (o *Observer) process(txns []string) {
	for _, txn := range txns {
		txnNode, err := o.TxnGraph.Read(txn)
		if err != nil {
			logger.Warnf("Failed to get txn node from txn graph: %s", txn, err.Error())

			continue
		}

		txnPayload, err := util.GetTransactionPayload(txnNode)
		if err != nil {
			logger.Warnf("Failed to extract transaction payload from txn[%s] for namespace [%s]: %s", txn, txnPayload.Namespace, err.Error()) //nolint:lll

			continue
		}

		pc, err := o.ProtocolClientProvider.ForNamespace(txnPayload.Namespace)
		if err != nil {
			logger.Warnf("Failed to get protocol client for namespace [%s]: %s", txnPayload.Namespace, err.Error())

			continue
		}

		v, err := pc.Get(txnPayload.Version)
		if err != nil {
			logger.Warnf("Failed to get processor for transaction time [%d]: %s", txnPayload.Version, err.Error())

			continue
		}

		sidetreeTxn := txnapi.SidetreeTxn{
			TransactionTime:     uint64(txnNode.Issued.Unix()),
			AnchorString:        txnPayload.AnchorString,
			Namespace:           txnPayload.Namespace,
			ProtocolGenesisTime: txnPayload.Version,
			Reference:           txn,
		}

		err = v.TransactionProcessor().Process(sidetreeTxn)
		if err != nil {
			logger.Warnf("failed to process anchor[%s]: %s", txnPayload.AnchorString, err.Error())

			continue
		}

		logger.Debugf("successfully processed anchor[%s]", txnPayload.AnchorString)
	}
}
