/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blockchain

import (
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/txnlog"
)

// Client implements blockchain client for writing anchors.
type Client struct {
	namespace string
	log       txnLog
	txnCh     chan []txn.SidetreeTxn
	sync.RWMutex
}

type txnLog interface {
	Append(info txnlog.Info) (txn.SidetreeTxn, error)
}

// New returns a new blockchain client.
func New(namespace string, log txnLog, txnCh chan []txn.SidetreeTxn) *Client {
	return &Client{
		namespace: namespace,
		log:       log,
		txnCh:     txnCh,
	}
}

// WriteAnchor writes anchor string to blockchain.
func (c *Client) WriteAnchor(anchor string, protocolGenesisTime uint64) error {
	txnInfo := txnlog.Info{
		AnchorString:        anchor,
		Namespace:           c.namespace,
		ProtocolGenesisTime: protocolGenesisTime,
	}

	tx, err := c.log.Append(txnInfo)
	if err != nil {
		return err
	}

	c.txnCh <- []txn.SidetreeTxn{tx}

	return nil
}

// Read reads transactions since transaction time.
func (c *Client) Read(_ int) (bool, *txn.SidetreeTxn) {
	// not used
	return false, nil
}
