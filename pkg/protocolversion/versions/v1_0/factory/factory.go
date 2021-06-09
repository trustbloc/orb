/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/didtransformer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/docvalidator/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/txnprovider"

	"github.com/trustbloc/orb/pkg/config"
	ctxcommon "github.com/trustbloc/orb/pkg/context/common"
	vcommon "github.com/trustbloc/orb/pkg/protocolversion/versions/common"
	protocolcfg "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/config"
	orboperationparser "github.com/trustbloc/orb/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchororigin"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchortime"
	"github.com/trustbloc/orb/pkg/versions/1_0/txnprocessor"
)

// Factory implements version 0.1 of the Sidetree protocol.
type Factory struct{}

// New returns a version 1.0 implementation of the Sidetree protocol.
func New() *Factory {
	return &Factory{}
}

// Create creates a new protocol version.
func (v *Factory) Create(version string, casClient cas.Client, casResolver ctxcommon.CASResolver,
	opStore ctxcommon.OperationStore, anchorGraph ctxcommon.AnchorGraph,
	sidetreeCfg config.Sidetree) (protocol.Version, error) {
	p := protocolcfg.GetProtocolConfig()

	opParser := operationparser.New(p,
		operationparser.WithAnchorTimeValidator(anchortime.New(p.MaxOperationTimeDelta)),
		operationparser.WithAnchorOriginValidator(anchororigin.New(sidetreeCfg.AnchorOrigins)))

	orbParser := orboperationparser.New(opParser)

	cp := compression.New(compression.WithDefaultAlgorithms())
	op := newOperationProviderWrapper(&p, opParser, casResolver, cp)
	oh := txnprovider.NewOperationHandler(p, casClient, cp, opParser)
	dc := doccomposer.New()
	oa := operationapplier.New(p, opParser, dc)

	dv := didvalidator.New(opStore)
	dt := didtransformer.New(
		didtransformer.WithMethodContext(sidetreeCfg.MethodContext),
		didtransformer.WithBase(sidetreeCfg.EnableBase))

	orbTxnProcessor := txnprocessor.New(
		&txnprocessor.Providers{
			OpStore:                   opStore,
			OperationProtocolProvider: op,
		},
	)

	return &vcommon.ProtocolVersion{
		VersionStr:     version,
		P:              p,
		TxnProcessor:   orbTxnProcessor,
		OpParser:       orbParser,
		OpApplier:      oa,
		DocComposer:    dc,
		OpHandler:      oh,
		OpProvider:     op,
		DocValidator:   dv,
		DocTransformer: dt,
	}, nil
}

type decompressionProvider interface {
	Decompress(alg string, data []byte) ([]byte, error)
}

// operationProviderWrapper wraps an OperationProvider with a CAS resolver that can fetch data using WebCAS.
type operationProviderWrapper struct {
	*txnprovider.OperationProvider

	*protocol.Protocol
	parser      txnprovider.OperationParser
	casResolver ctxcommon.CASResolver
	dp          decompressionProvider
}

// GetTxnOperations returns transaction operation from the underlying operation provider.
func (h *operationProviderWrapper) GetTxnOperations(transaction *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) { //nolint:lll
	casHint := ""

	if len(transaction.EquivalentReferences) > 0 {
		lastColonIndex := strings.LastIndex(transaction.EquivalentReferences[0], ":")

		casHint = transaction.EquivalentReferences[0][:lastColonIndex+1]
	}

	casClient := &casClientWrapper{
		resolver:                 h.casResolver,
		casHintWithTrailingColon: casHint,
	}

	op := txnprovider.NewOperationProvider(*h.Protocol, h.parser, casClient, h.dp)

	return op.GetTxnOperations(transaction)
}

type casClientWrapper struct {
	resolver                 ctxcommon.CASResolver
	casHintWithTrailingColon string
}

func (c *casClientWrapper) Read(cid string) ([]byte, error) {
	data, err := c.resolver.Resolve(nil, c.casHintWithTrailingColon+cid, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CID: %w", err)
	}

	return data, nil
}

func newOperationProviderWrapper(p *protocol.Protocol, parser *operationparser.Parser, resolver ctxcommon.CASResolver,
	cp *compression.Registry) *operationProviderWrapper {
	return &operationProviderWrapper{
		Protocol:    p,
		parser:      parser,
		casResolver: resolver,
		dp:          cp,
	}
}
