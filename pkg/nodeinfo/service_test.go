/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesmemstore "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const mongoDBConnString = "mongodb://localhost:27017"

type stringLogger struct {
	log string
}

func (s *stringLogger) Debugf(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Infof(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Warnf(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Errorf(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func TestService(t *testing.T) {
	log.SetLevel("nodeinfo", log.DEBUG)

	OrbVersion = "0.999"

	t.Run("Using MongoDB", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		mongoDBProvider, err := mongodb.NewProvider("mongodb://localhost:27017")
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

		s := NewService(serviceIRI, 50*time.Millisecond, apStore, true, nil)
		require.NotNil(t, s)

		logger := &stringLogger{}

		s.logger = logger

		s.updateStatsUsingMultiTagQuery()
		require.Contains(t, logger.log, "query ActivityPub outbox for Create activities: cannot run "+
			"query since the underlying storage provider does not support querying with multiple tags")
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

	s := NewService(serviceIRI, 50*time.Millisecond, apStore, multipleTagQueryCapable, nil)
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

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: "mongo",
		Tag:        "4.0.0",
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27017"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB() error {
	var err error

	clientOpts := options.Client().ApplyURI(mongoDBConnString)

	mongoClient, err := mongo.NewClient(clientOpts)
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return err
	}

	db := mongoClient.Database("test")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}
