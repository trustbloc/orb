/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
)

// New returns a new server context.
func New(pc protocol.Client, aw batch.AnchorWriter) *ServerContext {
	return &ServerContext{
		ProtocolClient: pc,
		AnchorWriter:   aw,
		OpQueue:        &opqueue.MemQueue{},
	}
}

// ServerContext implements batch context.
type ServerContext struct {
	ProtocolClient protocol.Client
	AnchorWriter   batch.AnchorWriter
	OpQueue        *opqueue.MemQueue
}

// Protocol returns the ProtocolClient.
func (m *ServerContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Anchor returns the anchor writer.
func (m *ServerContext) Anchor() batch.AnchorWriter {
	return m.AnchorWriter
}

// OperationQueue returns the queue containing the pending operations.
func (m *ServerContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}
