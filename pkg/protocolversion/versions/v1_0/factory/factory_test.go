/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"net/http"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

func TestFactory_Create(t *testing.T) {
	f := New()
	require.NotNil(t, f)

	casClient := &mocks.CasClient{}
	opStore := &mocks.OperationStore{}
	anchorGraph := &mocks.AnchorGraph{}
	casResolver := &mocks.CASResolver{}

	t.Run("success", func(t *testing.T) {
		pv, err := f.Create("1.0", casClient, casResolver, opStore, anchorGraph, config.Sidetree{})
		require.NoError(t, err)
		require.NotNil(t, pv)
	})
}

func TestCasReader_Read(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		cid, err := casClient.Write([]byte("sample data"))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		resolver := createNewResolver(t, casClient)

		reader := &casReader{
			resolver: resolver,
		}

		data, err := reader.Read(cid)
		require.NoError(t, err)
		require.Equal(t, "sample data", string(data))
	})
	t.Run("fail to resolve", func(t *testing.T) {
		resolver := createNewResolver(t, createInMemoryCAS(t))

		reader := &casReader{
			resolver: resolver,
		}

		data, err := reader.Read("QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ")
		require.Error(t, err)
		require.EqualError(t, err, "failed to resolve CID: failed to get data stored at "+
			"QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ from the local CAS: content not found")
		require.Nil(t, data)
	})
}

func createNewResolver(t *testing.T, casClient extendedcasclient.Client) *casresolver.Resolver {
	t.Helper()

	casResolver := casresolver.New(casClient, nil,
		casresolver.NewWebCASResolver(
			transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			webfingerclient.New(), "https"), &orbmocks.MetricsProvider{})
	require.NotNil(t, casResolver)

	return casResolver
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider(), "https://domain.com/cas", nil, &orbmocks.MetricsProvider{}, 0)

	require.NoError(t, err)

	return casClient
}
