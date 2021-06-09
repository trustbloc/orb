/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import (
	"testing"

	"github.com/stretchr/testify/require"

	cvmocks "github.com/trustbloc/orb/pkg/mocks"
	crmocks "github.com/trustbloc/orb/pkg/protocolversion/clientregistry/mocks"
	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ./mocks/clientfactory.gen.go --fake-name ClientFactory . factory
//go:generate counterfeiter -o ./../../mocks/clientversion.gen.go --fake-name ClientVersion github.com/trustbloc/orb/pkg/context/common.ClientVersion

func TestRegistry(t *testing.T) {
	const version = "0.1"

	f := &crmocks.ClientFactory{}
	f.CreateReturns(&cvmocks.ClientVersion{}, nil)

	r := New()

	require.NotPanics(t, func() { r.Register(version, f) })
	require.PanicsWithError(t, "client version factory [0.1] already registered", func() { r.Register(version, f) })

	casClient := &mocks.CasClient{}

	pv, err := r.CreateClientVersion(version, casClient)
	require.NoError(t, err)
	require.NotNil(t, pv)

	pv, err = r.CreateClientVersion("99", casClient)
	require.EqualError(t, err, "client version factory for version [99] not found")
	require.Nil(t, pv)
}
