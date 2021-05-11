/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
)

var logger = log.New("orb-observer")

// TxnProvider interface to access orb txn.
type TxnProvider interface {
	RegisterForAnchor() <-chan []anchorinfo.AnchorInfo
	RegisterForDID() <-chan []string
}

// AnchorGraph interface to access anchors.
type AnchorGraph interface {
	Read(cid string) (*verifiable.Credential, error)
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
	go o.listen(o.TxnProvider.RegisterForAnchor(), o.TxnProvider.RegisterForDID())
}

// Stop stops the observer.
func (o *Observer) Stop() {
	o.stopCh <- struct{}{}
}

func (o *Observer) listen(anchorCh <-chan []anchorinfo.AnchorInfo, didCh <-chan []string) {
	for {
		select {
		case <-o.stopCh:
			logger.Infof("The observer has been stopped. Exiting.")

			return

		case anchors, ok := <-anchorCh:
			if !ok {
				logger.Warnf("Anchor channel was closed. Exiting.")

				return
			}

			o.processAnchors(anchors)

		case dids, ok := <-didCh:
			if !ok {
				logger.Warnf("DID channel was closed. Exiting.")

				return
			}

			o.processDIDs(dids)
		}
	}
}

func (o *Observer) processAnchors(anchors []anchorinfo.AnchorInfo) {
	for _, anchor := range anchors {
		logger.Debugf("observing anchor: %s", anchor.CID)

		anchorInfo, err := o.AnchorGraph.Read(anchor.CID)
		if err != nil {
			logger.Warnf("Failed to get anchor[%s] node from anchor graph: %s", anchor.CID, err.Error())

			continue
		}

		logger.Debugf("successfully read anchor[%s] from anchor graph", anchor.CID)

		if err := o.processAnchor(anchor, anchorInfo); err != nil {
			logger.Warnf(err.Error())

			continue
		}
	}
}

func (o *Observer) processDIDs(dids []string) {
	for _, did := range dids {
		cid, suffix, err := getDidParts(did)
		if err != nil {
			logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

			return
		}

		anchors, err := o.AnchorGraph.GetDidAnchors(cid, suffix)
		if err != nil {
			logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

			return
		}

		for _, anchor := range anchors {
			// TODO (#364): Pass in a URL here that we can use to resolve data in CAS via WebFinger
			if err := o.processAnchor(anchorinfo.AnchorInfo{CID: anchor.CID, WebCASURL: &url.URL{}},
				anchor.Info, suffix); err != nil {
				logger.Warnf("ignoring anchor[%s] for did[%s]", anchor.CID, did, err.Error())

				continue
			}
		}
	}
}

func getDidParts(did string) (cid, suffix string, err error) {
	const delimiter = ":"

	const partNo = 2

	parts := strings.Split(did, delimiter)
	if len(parts) != partNo {
		return "", "", fmt.Errorf("invalid number of parts for did[%s]", did)
	}

	return parts[0], parts[1], nil
}

func (o *Observer) processAnchor(anchor anchorinfo.AnchorInfo, info *verifiable.Credential, suffixes ...string) error {
	logger.Debugf("processing anchor[%s], suffixes: %s", anchor.CID, suffixes)

	anchorPayload, err := util.GetAnchorSubject(info)
	if err != nil {
		return fmt.Errorf("failed to extract anchor payload from anchor[%s]: %w", anchor.CID, err)
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

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:     uint64(info.Issued.Unix()),
		AnchorString:        ad.GetAnchorString(),
		Namespace:           anchorPayload.Namespace,
		ProtocolGenesisTime: anchorPayload.Version,
		Reference:           anchor.WebCASURL.String(),
	}

	logger.Debugf("processing anchor[%s], core index[%s]", anchor.CID, anchorPayload.CoreIndex)

	err = v.TransactionProcessor().Process(sidetreeTxn, suffixes...)
	if err != nil {
		return fmt.Errorf("failed to processAnchors core index[%s]: %w", anchorPayload.CoreIndex, err)
	}

	logger.Debugf("successfully processed anchor[%s], core index[%s]", anchor.CID, anchorPayload.CoreIndex)

	return nil
}
