/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memlog

import (
	"sync"

	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/txnlog"
)

// Log implements in-memory transaction log.
type Log struct {
	txns []*txnapi.SidetreeTxn
	sync.RWMutex
}

// New creates new in-memory transaction log.
func New() *Log {
	return &Log{}
}

// Append adds anchor info to the log.
func (l *Log) Append(info txnlog.Info) error {
	l.Lock()

	index := len(l.txns)

	txn := &txnapi.SidetreeTxn{
		Namespace:           info.Namespace,
		TransactionTime:     uint64(index),
		TransactionNumber:   uint64(1), // TODO: one anchor per block (transaction time)
		AnchorString:        info.AnchorString,
		ProtocolGenesisTime: info.ProtocolGenesisTime,
	}

	l.txns = append(l.txns, txn)
	l.Unlock()

	return nil
}

// Read reads transactions since transaction number.
func (l *Log) Read(txnTime int64) ([]*txnapi.SidetreeTxn, error) {
	l.RLock()
	defer l.RUnlock()

	if txnTime >= int64(len(l.txns)-1) {
		return nil, nil
	}

	index := int64(0)
	if txnTime > -1 {
		index = txnTime + 1
	}

	anchors := l.txns[index:]

	return anchors, nil
}
