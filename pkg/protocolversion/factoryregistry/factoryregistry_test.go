/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factoryregistry

import (
	"testing"

	"github.com/stretchr/testify/require"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/config"
	frmocks "github.com/trustbloc/orb/pkg/protocolversion/factoryregistry/mocks"
	mocks "github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ./mocks/protocolfactory.gen.go --fake-name ProtocolFactory . factory
//go:generate counterfeiter -o ./../mocks/casclient.gen.go --fake-name CasClient github.com/trustbloc/sidetree-core-go/pkg/api/cas.Client
//go:generate counterfeiter -o ./../mocks/operationstore.gen.go --fake-name OperationStore github.com/trustbloc/orb/pkg/context/common.OperationStore
//go:generate counterfeiter -o ./../mocks/anchorgraph.gen.go --fake-name AnchorGraph github.com/trustbloc/orb/pkg/context/common.AnchorGraph
//go:generate counterfeiter -o ./../mocks/casresolver.gen.go --fake-name CASResolver github.com/trustbloc/orb/pkg/context/common.CASResolver

func TestRegistry(t *testing.T) {
	const version = "0.1"

	f := &frmocks.ProtocolFactory{}
	f.CreateReturns(&coremocks.ProtocolVersion{}, nil)

	r := New()

	require.NotPanics(t, func() { r.Register(version, f) })
	require.PanicsWithError(t, "protocol version factory [0.1] already registered", func() { r.Register(version, f) })

	casClient := &mocks.CasClient{}
	opStore := &mocks.OperationStore{}
	anchorGraph := &mocks.AnchorGraph{}
	casResolver := &mocks.CASResolver{}

	pv, err := r.CreateProtocolVersion(version, casClient, casResolver, opStore, anchorGraph, config.Sidetree{})
	require.NoError(t, err)
	require.NotNil(t, pv)

	pv, err = r.CreateProtocolVersion("99", casClient, casResolver, opStore, anchorGraph, config.Sidetree{})
	require.EqualError(t, err, "protocol version factory for version [99] not found")
	require.Nil(t, pv)
}
