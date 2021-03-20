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

// AnchorGraph interface to access anchors.
type AnchorGraph interface {
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
	AnchorGraph
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

func (o *Observer) listen(anchorCh <-chan []string) {
	for {
		select {
		case <-o.stopCh:
			logger.Infof("The observer has been stopped. Exiting.")

			return

		case anchors, ok := <-anchorCh:
			if !ok {
				logger.Warnf("Notification channel was closed. Exiting.")

				return
			}

			o.process(anchors)
		}
	}
}

func (o *Observer) process(anchors []string) {
	for _, anchor := range anchors {
		logger.Debugf("observing anchor cid: %s", anchor)

		anchorNode, err := o.AnchorGraph.Read(anchor)
		if err != nil {
			logger.Warnf("Failed to get anchor node from anchor graph: %s", anchor, err.Error())

			continue
		}

		logger.Debugf("successfully read anchor cid from anchor graph: %s", anchor)

		anchorPayload, err := util.GetAnchorSubject(anchorNode)
		if err != nil {
			logger.Warnf("Failed to extract anchor payload from anchor[%s] for namespace [%s]: %s", anchor, anchorPayload.Namespace, err.Error()) //nolint:lll

			continue
		}

		logger.Debugf("about to process core index: %s", anchorPayload.CoreIndex)

		pc, err := o.ProtocolClientProvider.ForNamespace(anchorPayload.Namespace)
		if err != nil {
			logger.Warnf("Failed to get protocol client for namespace [%s]: %s", anchorPayload.Namespace, err.Error())

			continue
		}

		v, err := pc.Get(anchorPayload.Version)
		if err != nil {
			logger.Warnf("Failed to get processor for transaction time [%d]: %s", anchorPayload.Version, err.Error())

			continue
		}

		ad := &util.AnchorData{OperationCount: anchorPayload.OperationCount, CoreIndexFileURI: anchorPayload.CoreIndex}

		sidetreeTxn := txnapi.SidetreeTxn{
			TransactionTime:     uint64(anchorNode.Issued.Unix()),
			AnchorString:        ad.GetAnchorString(),
			Namespace:           anchorPayload.Namespace,
			ProtocolGenesisTime: anchorPayload.Version,
			Reference:           anchor,
		}

		err = v.TransactionProcessor().Process(sidetreeTxn)
		if err != nil {
			logger.Warnf("failed to process anchor[%s]: %s", anchorPayload.CoreIndex, err.Error())

			continue
		}

		logger.Debugf("successfully processed anchor cid[%s], core index[%s]", anchor, anchorPayload.CoreIndex)
	}
}
