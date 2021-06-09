/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
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
	op := txnprovider.NewOperationProvider(p, opParser, casClient, cp)

	return &vcommon.ClientVersion{
		VersionStr: version,
		P:          p,
		OpProvider: op,
	}, nil
}
