/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"net/http"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	unpublishedopstore "github.com/trustbloc/orb/pkg/store/operation/unpublished"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

func TestFactory_Create(t *testing.T) {
	f := New()
	require.NotNil(t, f)

	casClient := &mocks.CasClient{}
	opStore := &mocks.OperationStore{}
	casResolver := &mocks.CASResolver{}
	storeProvider := &storemocks.Provider{}

	t.Run("success", func(t *testing.T) {
		pv, err := f.Create("1.0", casClient, casResolver, opStore, storeProvider, &config.Sidetree{}, nil)
		require.NoError(t, err)
		require.NotNil(t, pv)
	})

	t.Run("success - with update store config", func(t *testing.T) {
		updateDocumentStore, err := unpublishedopstore.New(storeProvider, time.Minute,
			testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		cfg := &config.Sidetree{
			UnpublishedOpStore:                      updateDocumentStore,
			UnpublishedOperationStoreOperationTypes: []operation.Type{operation.TypeUpdate},
		}

		pv, err := f.Create("1.0", casClient, casResolver, opStore, storeProvider, cfg, nil)
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

func TestFormatWebCASURI(t *testing.T) {
	t.Run("hash", func(t *testing.T) {
		casURI, err := formatWebCASURI("12345", "https://orb.domain1.com/services/orb")
		require.NoError(t, err)
		require.Equal(t, casURI, "https:orb.domain1.com:12345")
	})

	t.Run("hashlink", func(t *testing.T) {
		casURI, err := formatWebCASURI("hl:12345", "https://orb.domain1.com/services/orb")
		require.NoError(t, err)
		require.Equal(t, casURI, "https:orb.domain1.com:12345")
	})
}

func createNewResolver(t *testing.T, casClient extendedcasclient.Client) *casresolver.Resolver {
	t.Helper()

	casResolver := casresolver.New(casClient, nil,
		casresolver.NewWebCASResolver(
			transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
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
