/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"
	"net/http"
	"net/url"
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
	casresolver "github.com/trustbloc/orb/pkg/resolver/cas"
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
func (v *Factory) Create(version string, casClient cas.Client, opStore ctxcommon.OperationStore,
	anchorGraph ctxcommon.AnchorGraph, sidetreeCfg config.Sidetree) (protocol.Version, error) {
	//nolint:gomnd
	p := protocol.Protocol{
		GenesisTime:                  0,
		MultihashAlgorithms:          []uint{18},
		MaxOperationCount:            5000,
		MaxOperationSize:             2500,
		MaxOperationHashLength:       100,
		MaxDeltaSize:                 1700,
		MaxCasURILength:              100,
		CompressionAlgorithm:         "GZIP",
		MaxChunkFileSize:             10000000,
		MaxProvisionalIndexFileSize:  1000000,
		MaxCoreIndexFileSize:         1000000,
		MaxProofFileSize:             2500000,
		Patches:                      []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"}, //nolint:lll
		SignatureAlgorithms:          []string{"EdDSA", "ES256", "ES256K"},
		KeyAlgorithms:                []string{"Ed25519", "P-256", "secp256k1"},
		MaxMemoryDecompressionFactor: 3,
		NonceSize:                    16,
	}

	opParser := operationparser.New(p,
		operationparser.WithAnchorTimeValidator(anchortime.New(p.MaxOperationTimeDelta)),
		operationparser.WithAnchorOriginValidator(anchororigin.New(sidetreeCfg.AnchorOrigins)))

	orbParser := orboperationparser.New(opParser)

	cp := compression.New(compression.WithDefaultAlgorithms())
	op := newOperationProviderWrapper(&p, opParser, casresolver.New(casClient, &http.Client{}), cp)
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
			AnchorGraph:               anchorGraph,
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
	casResolver *casresolver.Resolver
	dp          decompressionProvider
}

// GetTxnOperations returns transaction operation from the underlying operation provider.
func (h *operationProviderWrapper) GetTxnOperations(transaction *txn.SidetreeTxn) ([]*operation.AnchoredOperation,
	error) {
	// The WebCAS endpoint will be of the form https://hostname/cas/{CID}.
	// We just want to remember this domain's CAS endpoint without the CID for the CAS client wrapper below.
	indexOfLastSlash := strings.LastIndex(transaction.Reference, "/")

	webCASEndpoint := transaction.Reference[:indexOfLastSlash+1]

	casClient := &casClientWrapper{
		resolver:       h.casResolver,
		webCASEndpoint: webCASEndpoint,
	}

	op := txnprovider.NewOperationProvider(*h.Protocol, h.parser, casClient, h.dp)

	return op.GetTxnOperations(transaction)
}

type casClientWrapper struct {
	resolver       *casresolver.Resolver
	webCASEndpoint string
}

func (c *casClientWrapper) Read(cid string) ([]byte, error) {
	webCASURL, err := url.Parse(c.webCASEndpoint + cid)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid URL: %w", c.webCASEndpoint+cid, err)
	}

	data, err := c.resolver.Resolve(webCASURL, cid, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CID: %w", err)
	}

	return data, nil
}

func newOperationProviderWrapper(p *protocol.Protocol, parser *operationparser.Parser, resolver *casresolver.Resolver,
	cp *compression.Registry) *operationProviderWrapper {
	return &operationProviderWrapper{
		Protocol:    p,
		parser:      parser,
		casResolver: resolver,
		dp:          cp,
	}
}
