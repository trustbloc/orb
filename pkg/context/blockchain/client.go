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
	sync.RWMutex
}

type txnLog interface {
	Append(info txnlog.Info) error
	Read(time int64) ([]*txn.SidetreeTxn, error)
}

// New returns a new blockchain client.
func New(namespace string, log txnLog) *Client {
	return &Client{
		namespace: namespace,
		log:       log,
	}
}

// WriteAnchor writes anchor string to blockchain.
func (c *Client) WriteAnchor(anchor string, protocolGenesisTime uint64) error {
	// TxnInfo contains info that gets recorded on blockchain as part of Sidetree transaction
	txnInfo := txnlog.Info{
		AnchorString:        anchor,
		Namespace:           c.namespace,
		ProtocolGenesisTime: protocolGenesisTime,
	}

	return c.log.Append(txnInfo)
}

// Read reads transactions since transaction time.
func (c *Client) Read(time int64) ([]*txn.SidetreeTxn, error) {
	return c.log.Read(time)
}
