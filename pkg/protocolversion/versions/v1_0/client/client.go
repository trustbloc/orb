/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/didtransformer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/docvalidator/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/txnprovider"

	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/context/common"
	vcommon "github.com/trustbloc/orb/pkg/protocolversion/versions/common"
	protocolcfg "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/config"
	orboperationparser "github.com/trustbloc/orb/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchortime"
)

// Factory implements version 0.1 of the client factory.
type Factory struct{}

// New returns a version 1.0 implementation of the Sidetree protocol.
func New() *Factory {
	return &Factory{}
}

// Create returns a 1.0 client version.
func (v *Factory) Create(version string, casClient common.CASReader, sidetreeCfg *config.Sidetree) (protocol.Version, error) {
	p := protocolcfg.GetProtocolConfig()

	var parserOpts []operationparser.Option
	parserOpts = append(parserOpts, operationparser.WithAnchorTimeValidator(anchortime.New(p.MaxOperationTimeDelta)))

	operationparser.WithAnchorOriginValidator(sidetreeCfg.AllowedOriginsValidator)

	opParser := operationparser.New(p, parserOpts...)

	orbParser := orboperationparser.New(opParser)

	cp := compression.New(compression.WithDefaultAlgorithms())

	dc := doccomposer.New()
	oa := operationapplier.New(p, opParser, dc)

	dv := didvalidator.New()
	dt := didtransformer.New(
		didtransformer.WithMethodContext(sidetreeCfg.MethodContext),
		didtransformer.WithBase(sidetreeCfg.EnableBase),
		didtransformer.WithIncludePublishedOperations(sidetreeCfg.IncludePublishedOperations),
		didtransformer.WithIncludeUnpublishedOperations(sidetreeCfg.IncludeUnpublishedOperations))

	op := txnprovider.NewOperationProvider(p, opParser, casClient, cp)

	return &vcommon.ProtocolVersion{
		VersionStr:     version,
		P:              p,
		OpProvider:     op,
		OpParser:       orbParser,
		OpApplier:      oa,
		DocComposer:    dc,
		DocValidator:   dv,
		DocTransformer: dt,
	}, nil
}
