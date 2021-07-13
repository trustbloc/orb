/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestService(t *testing.T) {
	log.SetLevel("nodeinfo", log.DEBUG)

	OrbVersion = "0.999"

	serviceIRI := testutil.MustParseURL("https://example.com/services/orb")

	const (
		numCreates = 10
		numLikes   = 5
	)

	apStore := memstore.New("")

	for _, a := range append(aptestutil.NewMockCreateActivities(numCreates),
		aptestutil.NewMockLikeActivities(numLikes)...) {
		require.NoError(t, apStore.AddActivity(a))
		require.NoError(t, apStore.AddReference(spi.Outbox, serviceIRI, a.ID().URL()))
	}

	s := NewService(apStore, serviceIRI, 50*time.Millisecond)
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
