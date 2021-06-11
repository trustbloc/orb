/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ThreeDotsLabs/watermill/message"
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
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// Providers contains all of the providers required by the TxnProcessor.
type Providers struct {
	ProtocolClientProvider protocol.ClientProvider
	AnchorGraph
	DidAnchors didAnchors
	PubSub     pubSub
}

// Observer receives transactions over a channel and processes them by storing them to an operation store.
type Observer struct {
	*Providers

	pubSub *PubSub
}

// New returns a new observer.
func New(providers *Providers) (*Observer, error) {
	o := &Observer{
		Providers: providers,
	}

	ps, err := NewPubSub(providers.PubSub, o.handleAnchor, o.processDID)
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
	logger.Debugf("observing anchor: %s", anchor.CID)

	anchorInfo, err := o.AnchorGraph.Read(anchor.CID)
	if err != nil {
		// TODO: Determine if error is transient so that it can be retried (issue #472).
		logger.Warnf("Failed to get anchor[%s] node from anchor graph: %s", anchor.CID, err.Error())

		return err
	}

	logger.Debugf("successfully read anchor[%s] from anchor graph", anchor.CID)

	if err := o.processAnchor(anchor, anchorInfo); err != nil {
		// TODO: Determine if error is transient so that it can be retried (issue #472).
		logger.Warnf(err.Error())

		return err
	}

	return nil
}

func (o *Observer) processDID(did string) error {
	logger.Debugf("processing out-of-system did[%s]", did)

	cidWithHint, suffix, err := getDidParts(did)
	if err != nil {
		logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

		return err
	}

	anchors, err := o.AnchorGraph.GetDidAnchors(cidWithHint, suffix)
	if err != nil {
		logger.Warnf("process did failed for did[%s]: %s", did, err.Error())

		// TODO: Determine if error is transient so that it can be retried (issue #472).

		return err
	}

	logger.Debugf("got %d anchors for out-of-system did[%s]", did)

	for _, anchor := range anchors {
		logger.Debugf("processing anchor[%s] for out-of-system did[%s]", anchor.CID, did)

		if err := o.processAnchor(&anchorinfo.AnchorInfo{CID: anchor.CID, WebCASURL: &url.URL{}},
			anchor.Info, suffix); err != nil {
			logger.Warnf("ignoring anchor[%s] for did[%s]", anchor.CID, did, err.Error())

			// TODO: Determine if error is transient. If so we can return the error and a retry will occur (issue #472).
			// If the error is persistent then continue with the next anchor.

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

func (o *Observer) processAnchor(anchor *anchorinfo.AnchorInfo, info *verifiable.Credential, suffixes ...string) error {
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

	equivalentRef := anchor.CID
	if anchor.Hint != "" {
		equivalentRef = anchor.Hint + ":" + equivalentRef
	} else {
		logger.Errorf("investigate: no hint provided for anchor[%s]", anchor.CID)
	}

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:      uint64(info.Issued.Unix()),
		AnchorString:         ad.GetAnchorString(),
		Namespace:            anchorPayload.Namespace,
		ProtocolGenesisTime:  anchorPayload.Version,
		CanonicalReference:   anchor.CID,
		EquivalentReferences: []string{equivalentRef},
	}

	logger.Debugf("processing anchor[%s], core index[%s]", anchor.CID, anchorPayload.CoreIndex)

	err = v.TransactionProcessor().Process(sidetreeTxn, suffixes...)
	if err != nil {
		return fmt.Errorf("failed to processAnchors core index[%s]: %w", anchorPayload.CoreIndex, err)
	}

	// update global did/anchor references
	acSuffixes := getKeys(anchorPayload.PreviousAnchors)

	err = o.DidAnchors.PutBulk(acSuffixes, equivalentRef)
	if err != nil {
		return fmt.Errorf("failed updating did anchor references for anchor credential[%s]: %w", anchor.CID, err)
	}

	logger.Debugf("successfully processed anchor[%s], core index[%s]", anchor.CID, anchorPayload.CoreIndex)

	return nil
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
