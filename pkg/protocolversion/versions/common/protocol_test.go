/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestProtocolVersion(t *testing.T) {
	p := &ProtocolVersion{
		VersionStr: "1.1",
		P: protocol.Protocol{
			GenesisTime: 1000,
		},
		TxnProcessor: &coremocks.TxnProcessor{},
		OpParser:     &coremocks.OperationParser{},
		OpApplier:    &coremocks.OperationApplier{},
		DocComposer:  &coremocks.DocumentComposer{},
		OpHandler:    &coremocks.OperationHandler{},
		OpProvider:   &coremocks.OperationProvider{},
		DocValidator: &coremocks.MockDocumentValidator{},
	}

	require.Equal(t, p.VersionStr, p.Version())
	require.Equal(t, p.P, p.Protocol())
	require.Equal(t, p.TxnProcessor, p.TransactionProcessor())
	require.Equal(t, p.OpParser, p.OperationParser())
	require.Equal(t, p.OpApplier, p.OperationApplier())
	require.Equal(t, p.DocComposer, p.DocumentComposer())
	require.Equal(t, p.OpHandler, p.OperationHandler())
	require.Equal(t, p.OpProvider, p.OperationProvider())
	require.Equal(t, p.DocValidator, p.DocumentValidator())
}
