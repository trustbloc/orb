/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/txnprovider"

	"github.com/trustbloc/orb/pkg/context/common"
	vcommon "github.com/trustbloc/orb/pkg/protocolversion/versions/common"
	protocolcfg "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/config"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchortime"
)

// Factory implements version 0.1 of the client factory.
type Factory struct{}

// New returns a version 1.0 implementation of the Sidetree protocol.
func New() *Factory {
	return &Factory{}
}

// Create returns a 1.0 client version.
func (v *Factory) Create(version string, casClient common.CASReader) (common.ClientVersion, error) {
	p := protocolcfg.GetProtocolConfig()

	opParser := operationparser.New(p, operationparser.WithAnchorTimeValidator(anchortime.New(p.MaxOperationTimeDelta)))

	cp := compression.New(compression.WithDefaultAlgorithms())

	op := newOperationProviderWrapper(&p, opParser, casClient, cp)

	return &vcommon.ClientVersion{
		VersionStr: version,
		P:          p,
		OpProvider: op,
	}, nil
}

type decompressionProvider interface {
	Decompress(alg string, data []byte) ([]byte, error)
}

// operationProviderWrapper wraps an OperationProvider with a CAS resolver that can fetch data using WebCAS.
type operationProviderWrapper struct {
	*txnprovider.OperationProvider

	*protocol.Protocol
	parser    txnprovider.OperationParser
	casReader common.CASReader
	dp        decompressionProvider
}

// GetTxnOperations returns transaction operation from the underlying operation provider.
func (h *operationProviderWrapper) GetTxnOperations(transaction *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) { //nolint:lll
	casHint := ""

	if len(transaction.EquivalentReferences) > 0 {
		lastColonIndex := strings.LastIndex(transaction.EquivalentReferences[0], ":")

		casHint = transaction.EquivalentReferences[0][:lastColonIndex+1]
	}

	casClient := &casClientWrapper{
		casReader:                h.casReader,
		casHintWithTrailingColon: casHint,
	}

	op := txnprovider.NewOperationProvider(*h.Protocol, h.parser, casClient, h.dp)

	return op.GetTxnOperations(transaction)
}

type casClientWrapper struct {
	casReader                common.CASReader
	casHintWithTrailingColon string
}

func (c *casClientWrapper) Read(cid string) ([]byte, error) {
	cidWithHint := c.casHintWithTrailingColon + cid

	data, err := c.casReader.Read(cidWithHint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cidWithHint[%s]: %w", cidWithHint, err)
	}

	return data, nil
}

func newOperationProviderWrapper(p *protocol.Protocol, parser *operationparser.Parser, casReader common.CASReader,
	cp *compression.Registry) *operationProviderWrapper {
	return &operationProviderWrapper{
		Protocol:  p,
		parser:    parser,
		casReader: casReader,
		dp:        cp,
	}
}
