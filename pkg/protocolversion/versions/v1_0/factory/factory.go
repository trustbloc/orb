/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
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
	"github.com/trustbloc/orb/pkg/store/operation/unpublished"
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
	opStore ctxcommon.OperationStore, provider storage.Provider,
	sidetreeCfg *config.Sidetree) (protocol.Version, error) {
	p := protocolcfg.GetProtocolConfig()

	opParser := operationparser.New(p,
		operationparser.WithAnchorTimeValidator(anchortime.New(p.MaxOperationTimeDelta)),
		operationparser.WithAnchorOriginValidator(anchororigin.New(sidetreeCfg.AnchorOrigins)))

	orbParser := orboperationparser.New(opParser)

	cp := compression.New(compression.WithDefaultAlgorithms())
	op := txnprovider.NewOperationProvider(p, opParser, &casReader{casResolver}, cp)
	oh := txnprovider.NewOperationHandler(p, casClient, cp, opParser)
	dc := doccomposer.New()
	oa := operationapplier.New(p, opParser, dc)

	dv := didvalidator.New()
	dt := didtransformer.New(
		didtransformer.WithMethodContext(sidetreeCfg.MethodContext),
		didtransformer.WithBase(sidetreeCfg.EnableBase),
		didtransformer.WithIncludePublishedOperations(sidetreeCfg.IncludePublishedOperations),
		didtransformer.WithIncludeUnpublishedOperations(sidetreeCfg.IncludeUnpublishedOperations))

	var orbTxnProcessorOpts []txnprocessor.Option

	if sidetreeCfg.UpdateDocumentStoreEnabled {
		updateDocumentStore, err := unpublished.New(provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create unpublished document store: %w", err)
		}

		orbTxnProcessorOpts = append(orbTxnProcessorOpts,
			txnprocessor.WithUnpublishedOperationStore(updateDocumentStore, sidetreeCfg.UpdateDocumentStoreTypes))
	}

	orbTxnProcessor := txnprocessor.New(
		&txnprocessor.Providers{
			OpStore:                   opStore,
			OperationProtocolProvider: op,
		},
		orbTxnProcessorOpts...,
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

type casReader struct {
	resolver ctxcommon.CASResolver
}

func (c *casReader) Read(cid string) ([]byte, error) {
	data, _, err := c.resolver.Resolve(nil, cid, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CID: %w", err)
	}

	return data, nil
}
