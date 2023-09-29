/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	svcprotocol "github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"
)

// ProtocolVersion implements the protocol.Version interface.
type ProtocolVersion struct {
	VersionStr     string
	P              protocol.Protocol
	TxnProcessor   svcprotocol.TxnProcessor
	OpParser       protocol.OperationParser
	OpApplier      protocol.OperationApplier
	DocComposer    protocol.DocumentComposer
	DocTransformer protocol.DocumentTransformer
	DocValidator   protocol.DocumentValidator
	OpHandler      svcprotocol.OperationHandler
	OpProvider     svcprotocol.OperationProvider
}

// Version returns the protocol parameters.
func (h *ProtocolVersion) Version() string {
	return h.VersionStr
}

// Protocol returns the protocol parameters.
func (h *ProtocolVersion) Protocol() protocol.Protocol {
	return h.P
}

// TransactionProcessor returns the transaction processor.
func (h *ProtocolVersion) TransactionProcessor() svcprotocol.TxnProcessor {
	return h.TxnProcessor
}

// OperationParser returns the operation parser.
func (h *ProtocolVersion) OperationParser() protocol.OperationParser {
	return h.OpParser
}

// OperationApplier returns the operation applier.
func (h *ProtocolVersion) OperationApplier() protocol.OperationApplier {
	return h.OpApplier
}

// DocumentComposer returns the document composer.
func (h *ProtocolVersion) DocumentComposer() protocol.DocumentComposer {
	return h.DocComposer
}

// OperationHandler returns the operation handler.
func (h *ProtocolVersion) OperationHandler() svcprotocol.OperationHandler {
	return h.OpHandler
}

// OperationProvider returns the operation provider.
func (h *ProtocolVersion) OperationProvider() svcprotocol.OperationProvider {
	return h.OpProvider
}

// DocumentValidator returns the document validator.
func (h *ProtocolVersion) DocumentValidator() protocol.DocumentValidator {
	return h.DocValidator
}

// DocumentTransformer returns the document transformer.
func (h *ProtocolVersion) DocumentTransformer() protocol.DocumentTransformer {
	return h.DocTransformer
}
