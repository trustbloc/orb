/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbtestutil

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const startingPort = 27016

var currentPort uint32 = startingPort //nolint:gochecknoglobals

// StartMongoDB starts a MongoDB Docker container. The connection string is returned,
// as well as a function that should be invoked to stop the Docker container when it is
// no longer required.
func StartMongoDB(t *testing.T) (connection string, stop func()) {
	t.Helper()

	pool, mongoDBResource, mongoDBConnString := startMongoDBContainer(t)

	return mongoDBConnString, func() {
		if pool != nil && mongoDBResource != nil {
			require.NoError(t, pool.Purge(mongoDBResource))
		}
	}
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource, string) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	const maxAttempts = 10

	for i := 0; i < maxAttempts; i++ {
		// Always use a new port since the tests periodically complain about port already in use.
		port := newPort()

		mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
			Repository: "mongo",
			Tag:        "4.0.0",
			PortBindings: map[dc.Port][]dc.PortBinding{
				"27017/tcp": {
					{HostIP: "", HostPort: fmt.Sprintf("%d", port)},
				},
			},
		})
		if err != nil {
			if strings.Contains(err.Error(), "port is already allocated") {
				t.Logf("Got error. Trying on another port: %s", err)

				continue
			}

			t.Fatalf("Unable to start Docker container: %s", err)
		}

		connectionString := fmt.Sprintf("mongodb://localhost:%d", port)

		require.NoError(t, waitForMongoDBToBeUp(t, connectionString))

		return pool, mongoDBResource, connectionString
	}

	panic(fmt.Sprintf("Unable to start Docker container after %d attempts", maxAttempts))
}

func waitForMongoDBToBeUp(t *testing.T, mongoDBConnString string) error {
	t.Helper()

	return backoff.Retry(func() error {
		t.Logf("Failed to ping MongoDB at %s. Retrying.", mongoDBConnString)

		return pingMongoDB(t, mongoDBConnString)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5))
}

func pingMongoDB(t *testing.T, mongoDBConnString string) error {
	t.Helper()

	var err error

	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(mongoDBConnString))
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return err
	}

	db := mongoClient.Database("test")

	const pingTimeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}

func newPort() uint32 {
	return atomic.AddUint32(&currentPort, 1)
}
