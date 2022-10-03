/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesmemstore "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
)

func TestService(t *testing.T) {
	log.SetLevel("nodeinfo", log.DEBUG)

	OrbVersion = "0.999"

	t.Run("Using MongoDB", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		apStore, err := ariesstore.New("", mongoDBProvider, true)
		require.NoError(t, err)

		runServiceTest(t, apStore, true)
	})
	t.Run("Using in-memory storage", func(t *testing.T) {
		apStore := memstore.New("")

		runServiceTest(t, apStore, false)
	})
}

func TestUpdateStatsUsingMultiTagQuery(t *testing.T) {
	t.Run("Fail to get total create activity count", func(t *testing.T) {
		serviceIRI := testutil.MustParseURL("https://example.com/services/orb")

		memProvider := ariesmemstore.NewProvider()

		apStore, err := ariesstore.New("", memProvider, false)
		require.NoError(t, err)

		s := NewService(serviceIRI, 50*time.Millisecond, apStore, true)
		require.NotNil(t, s)

		err = s.updateStatsUsingMultiTagQuery()
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"query ActivityPub outbox for Create activities: cannot run query since the underlying storage "+
				"provider does not support querying with multiple tags")
	})
}

func runServiceTest(t *testing.T, apStore spi.Store, multipleTagQueryCapable bool) {
	t.Helper()

	serviceIRI := testutil.MustParseURL("https://example.com/services/orb")

	const (
		numCreates = 10
		numLikes   = 5
	)

	for _, a := range append(aptestutil.NewMockCreateActivities(numCreates),
		aptestutil.NewMockLikeActivities(numLikes)...) {
		require.NoError(t, apStore.AddActivity(a))
		require.NoError(t, apStore.AddReference(spi.Outbox, serviceIRI, a.ID().URL(),
			spi.WithActivityType(a.Type().Types()[0])))
	}

	s := NewService(serviceIRI, 50*time.Millisecond, apStore, multipleTagQueryCapable)
	require.NotNil(t, s)

	s.Start()
	defer s.Stop()

	time.Sleep(500 * time.Millisecond)

	nodeInfo := s.GetNodeInfo(V2_0)
	require.NotNil(t, nodeInfo)

	require.Equal(t, "Orb", nodeInfo.Software.Name)
	require.Equal(t, "0.999", nodeInfo.Software.Version)
	require.Equal(t, "", nodeInfo.Software.Repository)
	require.False(t, nodeInfo.OpenRegistrations)
	require.Empty(t, nodeInfo.Services.Inbound)
	require.Empty(t, nodeInfo.Services.Outbound)
	require.Len(t, nodeInfo.Protocols, 1)
	require.Equal(t, activityPubProtocol, nodeInfo.Protocols[0])
	require.Empty(t, nodeInfo.Metadata)
	require.Equal(t, 1, nodeInfo.Usage.Users.Total)
	require.Equal(t, numCreates, nodeInfo.Usage.LocalPosts)
	require.Equal(t, numLikes, nodeInfo.Usage.LocalComments)

	nodeInfo = s.GetNodeInfo(V2_1)
	require.NotNil(t, nodeInfo)
	require.Equal(t, "Orb", nodeInfo.Software.Name)
	require.Equal(t, "0.999", nodeInfo.Software.Version)
	require.Equal(t, orbRepository, nodeInfo.Software.Repository)
	require.False(t, nodeInfo.OpenRegistrations)
	require.Empty(t, nodeInfo.Services.Inbound)
	require.Empty(t, nodeInfo.Services.Outbound)
	require.Len(t, nodeInfo.Protocols, 1)
	require.Equal(t, activityPubProtocol, nodeInfo.Protocols[0])
	require.Empty(t, nodeInfo.Metadata)
	require.Equal(t, 1, nodeInfo.Usage.Users.Total)
	require.Equal(t, numCreates, nodeInfo.Usage.LocalPosts)
	require.Equal(t, numLikes, nodeInfo.Usage.LocalComments)
}
