/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package expiry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const mongoDBConnString = "mongodb://localhost:27017"

type stringLogger struct {
	log  string
	lock sync.Mutex
}

func (s *stringLogger) Debugf(msg string, args ...interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Infof(msg string, args ...interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Errorf(msg string, args ...interface{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Read() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.log
}

func TestService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// This is a timing-based test.
		// Here's the timeline:
		// t=0s   --->  test data stored, expiry service started
		// t=4s   --->  data 1 is now expired, will get deleted on next check by expiry service (within 1s)
		// t=6s   --->  check to make sure data 1 was deleted
		// t=8s   --->  data 2 is now expired, will get deleted on next check by expiry service (within 1s)
		// t=10s  --->  check to make sure data 2 was deleted

		pool, mongoDBResource := startMongoDBContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		storeName := "TestStore"

		store, err := mongoDBProvider.OpenStore(storeName)
		require.NoError(t, err)

		expiryTagName := "ExpiryTime"

		err = mongoDBProvider.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{expiryTagName}})
		require.NoError(t, err)

		logger := log.New("expiry-service-test")

		data1ExpiryTime := time.Now().Add(time.Second * 4).Unix()
		data2ExpiryTime := time.Now().Add(time.Second * 8).Unix()
		data3ExpiryTime := time.Now().Add(time.Minute).Unix() // Far in the future - won't be expired during this test.

		logger.Infof("[Current Unix timestamp: %d] Data 1 will expire at %d, data 2 will expire at %d, "+
			"and data 3 will expire at %d.", time.Now().Unix(), data1ExpiryTime, data2ExpiryTime, data3ExpiryTime)

		operations := []storage.Operation{
			{
				Key:   "Key1",
				Value: []byte("TestValue1"),
				Tags: []storage.Tag{
					{
						Name:  expiryTagName,
						Value: fmt.Sprintf("%d", data1ExpiryTime),
					},
				},
			},
			{
				Key:   "Key2",
				Value: []byte("TestValue2"),
				Tags: []storage.Tag{
					{
						Name:  expiryTagName,
						Value: fmt.Sprintf("%d", data2ExpiryTime),
					},
				},
			},
			{
				Key:   "Key3",
				Value: []byte("TestValue3"),
				Tags: []storage.Tag{
					{
						Name:  expiryTagName,
						Value: fmt.Sprintf("%d", data3ExpiryTime),
					},
				},
			},
		}
		err = store.Batch(operations)
		require.NoError(t, err)

		logger.Infof("[Current Unix timestamp: %d] Successfully stored test data.", time.Now().Unix())

		log.SetLevel(loggerModule, log.DEBUG)

		service := NewService(time.Second)
		service.Register(store, expiryTagName, storeName)

		service.Start()
		defer service.Stop()

		waitTime := time.Second * 6

		logger.Infof("[Current Unix timestamp: %d] Waiting %s.", time.Now().Unix(), waitTime.String())

		time.Sleep(waitTime)

		logger.Infof("[Current Unix timestamp: %d] Finished waiting %s seconds. Checking to see if Key1 was "+
			"deleted as expected (while Key2 and Key3 remain since they haven't expired yet).",
			time.Now().Unix(), waitTime.String())

		_, err = store.Get("Key1")
		require.Equal(t, storage.ErrDataNotFound, err)

		logger.Infof("[Current Unix timestamp: %d] Key1 was deleted as expected.", time.Now().Unix())

		_, err = store.Get("Key2")
		require.NoError(t, err)

		logger.Infof("[Current Unix timestamp: %d] Key2 still remains as expected.", time.Now().Unix())

		_, err = store.Get("Key3")
		require.NoError(t, err)

		logger.Infof("[Current Unix timestamp: %d] Key3 still remains as expected.", time.Now().Unix())

		logger.Infof("[Current Unix timestamp: %d] Waiting %s.", time.Now().Unix(), waitTime.String())

		waitTime = time.Second * 4

		time.Sleep(waitTime)

		logger.Infof("[Current Unix timestamp: %d] Finished waiting %s. Checking to see if Key2 "+
			"was deleted as expected (while Key3 remains since it hasn't expired yet).",
			time.Now().Unix(), waitTime.String())

		_, err = store.Get("Key2")
		require.Equal(t, storage.ErrDataNotFound, err)

		logger.Infof("[Current Unix timestamp: %d] Key2 was deleted as expected.", time.Now().Unix())

		_, err = store.Get("Key3")
		require.NoError(t, err)

		logger.Infof("[Current Unix timestamp: %d] Key3 still remains as expected.", time.Now().Unix())
	})
	t.Run("Fail to query", func(t *testing.T) {
		store := &mock.Store{
			ErrQuery: errors.New("query error"),
		}

		service := NewService(time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		service.Start()
		defer service.Stop()

		time.Sleep(time.Millisecond * 2)

		require.Contains(t, logger.Read(), "failed to query store: query error")
	})
	t.Run("Fail to get next value from iterator", func(t *testing.T) {
		store := &mock.Store{
			QueryReturn: &mock.Iterator{ErrNext: errors.New("next error")},
		}

		service := NewService(time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		service.Start()
		defer service.Stop()

		time.Sleep(time.Millisecond * 2)

		require.Contains(t, logger.Read(), "failed to get next value from iterator: next error")
	})
	t.Run("Fail to get key from iterator", func(t *testing.T) {
		store := &mock.Store{
			QueryReturn: &mock.Iterator{NextReturn: true, ErrKey: errors.New("key error")},
		}

		service := NewService(time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		service.Start()
		defer service.Stop()

		time.Sleep(time.Millisecond * 2)

		require.Contains(t, logger.Read(), "failed to get key from iterator: key error")
	})
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
