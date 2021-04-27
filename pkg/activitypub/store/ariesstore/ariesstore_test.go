/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesstore_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kivik/kivik/v3"
	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	couchDBURL          = "admin:password@localhost:5984"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/testdata/single-node.ini:/opt/couchdb/etc/local.d/single-node.ini"
)

type mockStore struct {
	openStoreNameToFailOn      string
	setStoreConfigNameToFailOn string
}

func (m *mockStore) OpenStore(name string) (storage.Store, error) {
	if name == m.openStoreNameToFailOn {
		return nil, errors.New("open store error")
	}

	return nil, nil
}

func (m *mockStore) SetStoreConfig(name string, _ storage.StoreConfiguration) error {
	if name == m.setStoreConfigNameToFailOn {
		return errors.New("set store config error")
	}

	return nil
}

func (m *mockStore) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

func (m *mockStore) GetOpenStores() []storage.Store {
	panic("implement me")
}

func (m *mockStore) Close() error {
	panic("implement me")
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	path, err := filepath.Abs("./")
	if err != nil {
		panic(fmt.Sprintf("filepath: %v", err))
	}

	couchdbResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerCouchdbImage,
		Tag:        dockerCouchdbTag,
		Env:        []string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=password"},
		Mounts:     []string{fmt.Sprintf(dockerCouchdbVolume, path)},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5984"}},
		},
	})
	if err != nil {
		log.Println(`Failed to start CouchDB Docker image.` +
			` This can happen if there is a CouchDB container still running from a previous unit test run.` +
			` Try "docker ps" from the command line and kill the old container if it's still running.`)
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(couchdbResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkCouchDB(); err != nil {
		panic(fmt.Sprintf("check CouchDB: %v", err))
	}

	code = m.Run()
}

const retries = 30

func checkCouchDB() error {
	return backoff.Retry(func() error {
		return pingCouchDB(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

// pingCouchDB performs a readiness check on the CouchDB instance located at hostURL.
func pingCouchDB(hostURL string) error {
	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return err
	}

	const couchDBUsersTable = "_users"

	exists, err := client.DBExists(context.Background(), couchDBUsersTable)
	if err != nil {
		return fmt.Errorf("failed to probe couchdb for '%s' DB at %s: %w", couchDBUsersTable, hostURL, err)
	}

	if !exists {
		return fmt.Errorf(
			`"%s" database does not yet exist - CouchDB might not be fully initialized`, couchDBUsersTable)
	}

	return nil
}

func TestNew(t *testing.T) {
	t.Run("Failed to open activities store", func(t *testing.T) {
		provider, err := ariesstore.New(&mockStore{
			openStoreNameToFailOn: "activity",
		},
			"ServiceName")
		require.EqualError(t, err, "failed to open stores: failed to open activity store: open store error")
		require.Nil(t, provider)
	})
	t.Run("Failed to set store config on activities store", func(t *testing.T) {
		provider, err := ariesstore.New(&mockStore{
			setStoreConfigNameToFailOn: "activity",
		},
			"ServiceName")
		require.EqualError(t, err, "failed to open stores: failed to set store configuration on "+
			"activity store: set store config error")
		require.Nil(t, provider)
	})
	t.Run("Failed to open inbox store", func(t *testing.T) {
		provider, err := ariesstore.New(&mockStore{
			openStoreNameToFailOn: string(spi.Inbox),
		},
			"ServiceName")
		require.EqualError(t, err, "failed to open stores: failed to open reference stores: "+
			"failed to open INBOX store: open store error")
		require.Nil(t, provider)
	})
	t.Run("Failed to set store config on inbox store", func(t *testing.T) {
		provider, err := ariesstore.New(&mockStore{
			setStoreConfigNameToFailOn: string(spi.Inbox),
		},
			"ServiceName")
		require.EqualError(t, err, "failed to open stores: failed to open reference stores: "+
			"failed to set store configuration on INBOX store: set store config error")
		require.Nil(t, provider)
	})
	t.Run("Failed to open actor store", func(t *testing.T) {
		provider, err := ariesstore.New(&mockStore{
			openStoreNameToFailOn: "actor",
		},
			"ServiceName")
		require.EqualError(t, err, "failed to open stores: failed to open actor store: open store error")
		require.Nil(t, provider)
	})
}

func TestStore_Activity(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		serviceName := generateRandomServiceName()
		couchDBProvider, err := ariescouchdbstorage.NewProvider(couchDBURL, ariescouchdbstorage.WithDBPrefix(serviceName))
		require.NoError(t, err)

		s, err := ariesstore.New(couchDBProvider, serviceName)
		require.NoError(t, err)

		serviceID1 := testutil.MustParseURL("https://example.com/services/service1")
		activityID1 := testutil.MustParseURL("https://example.com/activities/activity1")
		activityID2 := testutil.MustParseURL("https://example.com/activities/activity2")
		activityID3 := testutil.MustParseURL("https://example.com/activities/activity3")

		a, err := s.GetActivity(activityID1)
		require.Error(t, err)
		require.True(t, errors.Is(err, spi.ErrNotFound))
		require.Nil(t, a)

		activity1 := vocab.NewCreateActivity(vocab.NewObjectProperty(vocab.WithIRI(serviceID1)),
			vocab.WithID(activityID1))
		require.NoError(t, s.AddActivity(activity1))

		receivedActivity1, err := s.GetActivity(activityID1)
		require.NoError(t, err)

		receivedActivity1Bytes, err := receivedActivity1.MarshalJSON()
		require.NoError(t, err)

		expectedActivity1Bytes, err := activity1.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, string(expectedActivity1Bytes), string(receivedActivity1Bytes))

		activity2 := vocab.NewAnnounceActivity(vocab.NewObjectProperty(vocab.WithIRI(serviceID1)),
			vocab.WithID(activityID2))
		require.NoError(t, s.AddActivity(activity2))

		activity3 := vocab.NewCreateActivity(vocab.NewObjectProperty(vocab.WithIRI(serviceID1)),
			vocab.WithID(activityID3))
		require.NoError(t, s.AddActivity(activity3))

		require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID1))
		require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID2))
		require.NoError(t, s.AddReference(spi.Inbox, serviceID1, activityID3))

		t.Run("Query all", func(t *testing.T) {
			t.Run("Ascending (default) order", func(t *testing.T) {
				it, err := s.QueryActivities(spi.NewCriteria())
				require.NoError(t, err)
				require.NotNil(t, it)

				checkActivityQueryResultsInOrder(t, it, activityID1, activityID2, activityID3)

				// Currently Aries store doesn't TotalItems, so it always returns 0.
				require.Equal(t, 0, it.TotalItems())

				// With CouchDB, closing the iterator isn't necessary. Instead of calling it.Close() for every test,
				// We'll just check it once here in order to increase code coverage.
				require.NoError(t, it.Close())
			})
			t.Run("Descending order", func(t *testing.T) {
				it, err := s.QueryActivities(spi.NewCriteria(), spi.WithSortOrder(spi.SortDescending))
				require.NoError(t, err)
				require.NotNil(t, it)

				checkActivityQueryResultsInOrder(t, it, activityID3, activityID2, activityID1)

				// Currently Aries store doesn't TotalItems, so it always returns 0.
				require.Equal(t, 0, it.TotalItems())
			})
		})

		t.Run("Query by reference", func(t *testing.T) {
			t.Run("Ascending (default) order", func(t *testing.T) {
				it, err := s.QueryActivities(
					spi.NewCriteria(spi.WithReferenceType(spi.Inbox), spi.WithObjectIRI(serviceID1)))
				require.NoError(t, err)
				require.NotNil(t, it)

				checkActivityQueryResultsInOrder(t, it, activityID1, activityID2, activityID3)
			})
			t.Run("Descending order", func(t *testing.T) {
				it, err := s.QueryActivities(
					spi.NewCriteria(spi.WithReferenceType(spi.Inbox), spi.WithObjectIRI(serviceID1)),
					spi.WithSortOrder(spi.SortDescending))
				require.NoError(t, err)
				require.NotNil(t, it)

				checkActivityQueryResultsInOrder(t, it, activityID3, activityID2, activityID1)
			})
		})
	})
	t.Run("Fail to add activity", func(t *testing.T) {
		provider, err := ariesstore.New(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrPut: errors.New("put error"),
			},
		},
			"ServiceName")
		require.NoError(t, err)

		serviceID1 := testutil.MustParseURL("https://example.com/services/service1")

		activityID1 := testutil.MustParseURL("https://example.com/activities/activity1")

		err = provider.AddActivity(vocab.NewCreateActivity(vocab.NewObjectProperty(vocab.WithIRI(serviceID1)),
			vocab.WithID(activityID1)))
		require.EqualError(t, err, "failed to store activity: put error")
	})
	t.Run("Fail to get activity", func(t *testing.T) {
		provider, err := ariesstore.New(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrGet: errors.New("get error"),
			},
		},
			"ServiceName")
		require.NoError(t, err)

		_, err = provider.GetActivity(testutil.MustParseURL("https://example.com/activities/activity1"))
		require.EqualError(t, err, "unexpected failure while getting activity from store: get error")
	})
	t.Run("Fail to query", func(t *testing.T) {
		provider, err := ariesstore.New(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrQuery: errors.New("query error"),
			},
		},
			"ServiceName")
		require.NoError(t, err)

		_, err = provider.QueryActivities(spi.NewCriteria())
		require.EqualError(t, err, "failed to query store: query error")
	})
	t.Run("Unsupported query criteria", func(t *testing.T) {
		provider, err := ariesstore.New(mem.NewProvider(),
			"ServiceName")
		require.NoError(t, err)

		serviceID1 := testutil.MustParseURL("https://example.com/services/service1")

		_, err = provider.QueryActivities(spi.NewCriteria(spi.WithObjectIRI(serviceID1),
			spi.WithActivityIRIs(testutil.MustParseURL("https://example.com/activities/activity1"),
				testutil.MustParseURL("https://example.com/activities/activity1"))))
		require.EqualError(t, err, "unsupported query criteria")
	})
}

func TestStore_Actors(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		serviceName := generateRandomServiceName()
		couchDBProvider, err := ariescouchdbstorage.NewProvider(couchDBURL, ariescouchdbstorage.WithDBPrefix(serviceName))
		require.NoError(t, err)

		s, err := ariesstore.New(couchDBProvider, serviceName)
		require.NoError(t, err)

		actor1IRI := testutil.MustParseURL("https://actor1")
		actor2IRI := testutil.MustParseURL("https://actor2")

		a, err := s.GetActor(actor1IRI)
		require.EqualError(t, err, spi.ErrNotFound.Error())
		require.Nil(t, a)

		actor1 := vocab.NewService(actor1IRI)
		actor2 := vocab.NewService(actor2IRI)

		require.NoError(t, s.PutActor(actor1))
		require.NoError(t, s.PutActor(actor2))

		receivedActor1, err := s.GetActor(actor1IRI)
		require.NoError(t, err)

		expectedActor1Bytes, err := actor1.MarshalJSON()
		require.NoError(t, err)

		receivedActor1Bytes, err := receivedActor1.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, string(expectedActor1Bytes), string(receivedActor1Bytes))

		receivedActor2, err := s.GetActor(actor2IRI)
		require.NoError(t, err)

		expectedActor2Bytes, err := actor2.MarshalJSON()
		require.NoError(t, err)

		receivedActor2Bytes, err := receivedActor2.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, string(expectedActor2Bytes), string(receivedActor2Bytes))
	})
	t.Run("Fail to put actor", func(t *testing.T) {
		provider, err := ariesstore.New(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrPut: errors.New("put error"),
			},
		},
			"ServiceName")
		require.NoError(t, err)

		err = provider.PutActor(vocab.NewService(testutil.MustParseURL("https://actor1")))
		require.EqualError(t, err, "failed to store actor: put error")
	})
	t.Run("Fail to get actor", func(t *testing.T) {
		provider, err := ariesstore.New(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrGet: errors.New("get error"),
			},
		},
			"ServiceName")
		require.NoError(t, err)

		_, err = provider.GetActor(testutil.MustParseURL("https://actor1"))
		require.EqualError(t, err, "unexpected failure while getting actor from store: get error")
	})
}

func TestStore_Reference(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		serviceName := generateRandomServiceName()
		couchDBProvider, err := ariescouchdbstorage.NewProvider(couchDBURL, ariescouchdbstorage.WithDBPrefix(serviceName))
		require.NoError(t, err)

		s, err := ariesstore.New(couchDBProvider, serviceName)
		require.NoError(t, err)

		actor1 := testutil.MustParseURL("https://actor1")
		actor2 := testutil.MustParseURL("https://actor2")
		actor3 := testutil.MustParseURL("https://actor3")

		it, err := s.QueryReferences(spi.Follower, spi.NewCriteria())
		require.EqualError(t, err, "object IRI is required")
		require.Nil(t, it)

		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
		require.NoError(t, err)
		require.NotNil(t, it)

		checkReferenceQueryResultsInOrder(t, it)
		// Currently Aries store doesn't support TotalItems, so it always returns 0.
		require.Equal(t, 0, it.TotalItems())

		require.NoError(t, s.AddReference(spi.Follower, actor1, actor2))
		require.NoError(t, s.AddReference(spi.Follower, actor1, actor3))

		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor2, actor3)

		// Try the same query as above, but in descending order this time
		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)),
			spi.WithSortOrder(spi.SortDescending))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor3, actor2)

		it, err = s.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actor1)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it)

		require.NoError(t, s.AddReference(spi.Following, actor1, actor2))

		it, err = s.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actor1)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor2)

		require.NoError(t, s.DeleteReference(spi.Follower, actor1, actor2))

		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor1)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor3)

		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor2)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it)

		require.NoError(t, s.AddReference(spi.Follower, actor2, actor3))

		it, err = s.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(actor2)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor3)

		// With CouchDB, closing the iterator isn't necessary. Instead of calling it.Close() again and again above,
		// We'll run it.Close() just once at the end in order to increase code coverage.
		// Note that the query call below returns an in-memory iterator, which is already
		// covered in the in-memory store tests, hence why we're doing it.Close() now.
		require.NoError(t, it.Close())

		it, err = s.QueryReferences(spi.Follower,
			spi.NewCriteria(spi.WithObjectIRI(actor2), spi.WithReferenceIRI(actor3)))
		require.NoError(t, err)

		checkReferenceQueryResultsInOrder(t, it, actor3)
	})
	t.Run("Fail to add reference", func(t *testing.T) {
		t.Run("Fail to store in underlying storage", func(t *testing.T) {
			provider, err := ariesstore.New(&mock.Provider{
				OpenStoreReturn: &mock.Store{
					ErrPut: errors.New("put error"),
				},
			},
				"ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")
			actor2 := testutil.MustParseURL("https://actor2")

			err = provider.AddReference(spi.Following, actor1, actor2)
			require.EqualError(t, err, "failed to store reference: put error")
		})
		t.Run("No store found for the reference type", func(t *testing.T) {
			provider, err := ariesstore.New(mem.NewProvider(), "ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")
			actor2 := testutil.MustParseURL("https://actor2")

			err = provider.AddReference("UnknownReferenceType", actor1, actor2)
			require.EqualError(t, err, "no store found for UnknownReferenceType")
		})
	})
	t.Run("Fail to delete reference", func(t *testing.T) {
		t.Run("Fail to delete in underlying storage", func(t *testing.T) {
			provider, err := ariesstore.New(&mock.Provider{
				OpenStoreReturn: &mock.Store{
					ErrDelete: errors.New("delete error"),
				},
			},
				"ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")
			actor2 := testutil.MustParseURL("https://actor2")

			err = provider.DeleteReference(spi.Following, actor1, actor2)
			require.EqualError(t, err, "failed to delete reference: delete error")
		})
		t.Run("No store found for the reference type", func(t *testing.T) {
			provider, err := ariesstore.New(mem.NewProvider(), "ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")
			actor2 := testutil.MustParseURL("https://actor2")

			err = provider.DeleteReference("UnknownReferenceType", actor1, actor2)
			require.EqualError(t, err, "no store found for UnknownReferenceType")
		})
	})
	t.Run("Fail to query references", func(t *testing.T) {
		t.Run("Fail to query in underlying storage", func(t *testing.T) {
			provider, err := ariesstore.New(&mock.Provider{
				OpenStoreReturn: &mock.Store{
					ErrQuery: errors.New("query error"),
				},
			},
				"ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")

			_, err = provider.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actor1)))
			require.EqualError(t, err, "failed to query store: query error")
		})
		t.Run("No store found for the reference type", func(t *testing.T) {
			provider, err := ariesstore.New(mem.NewProvider(), "ServiceName")
			require.NoError(t, err)

			actor1 := testutil.MustParseURL("https://actor1")

			_, err = provider.QueryReferences("UnknownReferenceType",
				spi.NewCriteria(spi.WithObjectIRI(actor1)))
			require.EqualError(t, err, "no store found for UnknownReferenceType")
		})
	})
}

func checkActivityQueryResultsInOrder(t *testing.T, it spi.ActivityIterator, expectedActivities ...*url.URL) {
	t.Helper()

	require.NotNil(t, it)

	for i := 0; i < len(expectedActivities); i++ {
		retrievedActivity, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, retrievedActivity)
		require.Equal(t, expectedActivities[i].String(), retrievedActivity.ID().URL().String())
	}

	retrievedActivity, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, retrievedActivity)
}

func checkReferenceQueryResultsInOrder(t *testing.T, it spi.ReferenceIterator, expectedIRIs ...*url.URL) {
	t.Helper()

	require.NotNil(t, it)

	for i := 0; i < len(expectedIRIs); i++ {
		iri, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, iri)
		require.Equal(t, expectedIRIs[i].String(), iri.String())
	}

	iri, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, iri)
}

// The "service_" part is necessary to ensure the database doesn't start with a number, which is not allowed
// by CouchDB.
func generateRandomServiceName() string {
	return "service_" + uuid.NewString()
}
