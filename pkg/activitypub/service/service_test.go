/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/httpsig"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const cid = "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

var (
	host1        = testutil.MustParseURL("https://sally.example.com")
	anchorCredID = testutil.NewMockID(host1, "/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")
)

func TestNewService(t *testing.T) {
	cfg1 := &Config{
		ServiceEndpoint: "/services/service1",
		PubSubFactory: func(serviceName string) PubSub {
			return mocks.NewPubSub()
		},
	}

	store1 := memstore.New(cfg1.ServiceEndpoint)
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := New(cfg1, store1, transport.Default(), &mocks.SignatureVerifier{},
		service.WithUndeliverableHandler(undeliverableHandler1))
	require.NoError(t, err)

	stop := startHTTPServer(t, ":8311", service1.InboxHTTPHandler())
	defer stop()

	service1.Start()

	require.Equal(t, service.StateStarted, service1.State())

	service1.Stop()

	require.Equal(t, service.StateStopped, service1.State())
}

func TestService_Create(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	unavailableServiceIRI := testutil.MustParseURL("http://localhost:8304/services/service4")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))

	require.NoError(t, store1.PutActor(actor1))
	require.NoError(t, store1.PutActor(aptestutil.NewMockService(service2IRI)))
	require.NoError(t, store1.PutActor(aptestutil.NewMockService(unavailableServiceIRI)))

	defer service1.Stop()

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	service2, store2, _, mockProviders2 := newServiceWithMocks(t, "/services/service2", service2IRI)

	mockProviders2.actorRetriever.WithPublicKey(publicKey1).WithActor(actor1)

	defer service2.Stop()

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	service1.Start()

	// delay the start of Service2 to test redelivery
	go func() {
		time.Sleep(50 * time.Millisecond)
		service2.Start()
	}()

	defer service1.Stop()
	defer service2.Stop()

	targetProperty := vocab.NewObjectProperty(vocab.WithObject(
		vocab.NewObject(
			vocab.WithID(anchorCredID),
			vocab.WithCID(cid),
			vocab.WithType(vocab.TypeContentAddressedStorage),
		),
	))

	obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
	if err != nil {
		panic(err)
	}

	create := vocab.NewCreateActivity(
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithTarget(targetProperty),
		vocab.WithContext(vocab.ContextOrb),
		vocab.WithTo(service2IRI, unavailableServiceIRI),
	)

	createID, err := service1.Outbox().Post(create)
	require.NoError(t, err)
	require.NotNil(t, createID)

	time.Sleep(1500 * time.Millisecond)

	it, err := store1.QueryActivities(
		spi.NewCriteria(
			spi.WithObjectIRI(service1IRI),
			spi.WithReferenceType(spi.Outbox),
		))
	require.NoError(t, err)
	require.NotNil(t, it)

	activities, err := storeutil.ReadActivities(it, -1)
	require.NoError(t, err)
	require.True(t, containsActivity(activities, create.ID()))

	it, err = store2.QueryActivities(
		spi.NewCriteria(
			spi.WithObjectIRI(service2IRI),
			spi.WithReferenceType(spi.Inbox),
		))
	require.NoError(t, err)
	require.NotNil(t, it)

	activities, err = storeutil.ReadActivities(it, -1)
	require.NoError(t, err)
	require.True(t, containsActivity(activities, create.ID()))

	require.NotEmpty(t, subscriber2.Activities())
	require.NotEmpty(t, mockProviders2.anchorCredentialHandler.AnchorCred(anchorCredID.String()))

	ua := mockProviders1.undeliverableHandler.Activities()
	require.Len(t, ua, 1)
	require.Equal(t, testutil.NewMockID(unavailableServiceIRI, resthandler.InboxPath).String(), ua[0].ToURL)
}

func TestService_Follow(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

	defer service1.Stop()

	service2, store2, publicKey2, mockProviders2 := newServiceWithMocks(t, "/services/service2", service2IRI)

	defer service2.Stop()

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))
	actor2 := aptestutil.NewMockService(service2IRI, aptestutil.WithPublicKey(publicKey2))

	require.NoError(t, store1.PutActor(actor2))
	require.NoError(t, store2.PutActor(actor1))

	mockProviders1.actorRetriever.WithPublicKey(publicKey2).WithActor(actor2)
	mockProviders2.actorRetriever.WithPublicKey(publicKey1).WithActor(actor1)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	httpServer2 := httpserver.New(":8302", "", "", "", service2.InboxHTTPHandler())

	defer func() {
		require.NoError(t, httpServer2.Stop(context.Background()))
	}()

	service1.Start()

	// delay the start of Service2 to test redelivery
	go func() {
		time.Sleep(50 * time.Millisecond)
		service2.Start()
		require.NoError(t, httpServer2.Start())
	}()

	defer service1.Stop()
	defer service2.Stop()

	t.Run("Follow - Accept", func(t *testing.T) {
		mockProviders2.followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		)

		activityID, err := service1.Outbox().Post(follow)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		it, err := store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, follow.ID()))

		it, err = store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, follow.ID()))

		rit, err := store1.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(service1IRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, following)
		require.Truef(t, containsIRI(following, service2IRI), "expecting %s to be following %s", service1IRI, service2IRI)

		rit, err = store2.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)

		require.NotEmpty(t, followers)
		require.Truef(t, containsIRI(followers, service1IRI), "expecting %s to have %s as a follower",
			service2IRI, service1IRI)

		// Ensure we have an 'Accept' activity in our inbox
		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)

		for _, a := range activities {
			if a.Type().Is(vocab.TypeAccept) {
				acceptedFollow := a.Object().Activity()
				require.NotNil(t, acceptedFollow)
				require.Equal(t, follow.ID(), acceptedFollow.ID())
			}
		}
	})

	t.Run("Follow - Reject", func(t *testing.T) {
		mockProviders1.followerAuth.WithReject()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		for i := 0; i < 5; i++ {
			// Wait for the service to start
			_, err := service2.Outbox().Post(follow)
			if err == nil {
				break
			}

			if !errors.Is(err, service.ErrNotStarted) {
				t.Fatal(err)
			}

			t.Logf("Service2 hasn't started yet. Waiting...")

			time.Sleep(50 * time.Millisecond)
		}

		// Wait for the message to be processed
		time.Sleep(500 * time.Millisecond)

		it, err := store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, follow.ID()))

		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, follow.ID()))

		rit, err := store1.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(following, service1IRI), "expecting %s NOT to be following %s",
			service2IRI, service1IRI)

		rit, err = store1.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(service1IRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(followers, service2IRI), "expecting %s NOT to have %s as a follower",
			service1IRI, service2IRI)

		// Ensure we have a 'Reject' activity in our inbox
		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)

		for _, a := range activities {
			if a.Type().Is(vocab.TypeReject) {
				rejectedFollow := a.Object().Activity()
				require.NotNil(t, rejectedFollow)
				require.Equal(t, follow.ID(), rejectedFollow.ID())
			}
		}
	})
}

func TestService_Announce(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)
	log.SetLevel("activitypub_service", log.DEBUG)
	log.SetLevel("activitypub_client", log.DEBUG)
	log.SetLevel("activitypub_httpsig", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	service1, store1, publicKey1, _ := newServiceWithMocks(t, "/services/service1", service1IRI)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	service2, store2, publicKey2, mockProviders2 := newServiceWithMocks(t, "/services/service2", service2IRI)

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	service3, store3, publicKey3, mockProviders3 := newServiceWithMocks(t, "/services/service3", service3IRI)

	stop3 := startHTTPServer(t, ":8303", service3.InboxHTTPHandler())
	defer stop3()

	subscriber3 := mocks.NewSubscriber(service3.Subscribe())

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))
	actor2 := aptestutil.NewMockService(service2IRI, aptestutil.WithPublicKey(publicKey2))
	actor3 := aptestutil.NewMockService(service3IRI, aptestutil.WithPublicKey(publicKey3))

	mockProviders2.actorRetriever.
		WithPublicKey(publicKey1).WithActor(actor1).
		WithPublicKey(publicKey3).WithActor(actor3)

	mockProviders3.actorRetriever.
		WithPublicKey(publicKey2).WithActor(actor2)

	require.NoError(t, store1.PutActor(actor2))
	require.NoError(t, store2.PutActor(actor3))

	service1.Start()
	service2.Start()
	service3.Start()

	defer service1.Stop()
	defer service2.Stop()
	defer service3.Stop()

	t.Run("Announce - anchor credential ref (no embedded object)", func(t *testing.T) {
		ref := vocab.NewAnchorCredentialReference(newActivityID(service2IRI), anchorCredID, cid)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithTo(service3IRI),
			vocab.WithPublishedTime(&published),
		)

		activityID, err := service2.Outbox().Post(announce)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		it, err := store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, announce.ID()))

		it, err = store3.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service3IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, announce.ID()))

		require.NotEmpty(t, subscriber3.Activities())

		require.NotEmpty(t, mockProviders3.anchorCredentialHandler.AnchorCred(anchorCredID.String()))
	})

	t.Run("Announce - anchor credential ref (with embedded object)", func(t *testing.T) {
		ref, err := vocab.NewAnchorCredentialReferenceWithDocument(newTransactionID(service2IRI), anchorCredID,
			cid, vocab.MustUnmarshalToDoc([]byte(anchorCredential1)),
		)
		require.NoError(t, err)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithTo(service3IRI),
			vocab.WithPublishedTime(&published),
		)

		activityID, err := service2.Outbox().Post(announce)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		it, err := store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, announce.ID()))

		it, err = store3.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service3IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, announce.ID()))

		require.NotEmpty(t, subscriber3.Activities())

		require.NotEmpty(t, mockProviders3.anchorCredentialHandler.AnchorCred(anchorCredID.String()))
	})

	t.Run("Create and announce", func(t *testing.T) {
		// Service3 requests to follow Service2

		require.NoError(t, store2.PutActor(vocab.NewService(service3IRI,
			vocab.WithInbox(testutil.NewMockID(service3IRI, resthandler.InboxPath)))))
		require.NoError(t, store3.PutActor(vocab.NewService(service2IRI,
			vocab.WithInbox(testutil.NewMockID(service2IRI, resthandler.InboxPath)))))

		mockProviders2.followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		)

		activityID, err := service3.Outbox().Post(follow)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		rit, err := store2.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, followers)
		require.Truef(t, containsIRI(followers, service3IRI), "expecting %s to have %s as a follower",
			service2IRI, service3IRI)

		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3z"

		targetProperty := vocab.NewObjectProperty(vocab.WithObject(
			vocab.NewObject(
				vocab.WithID(anchorCredID),
				vocab.WithCID(cid),
				vocab.WithType(vocab.TypeContentAddressedStorage),
			),
		))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		if err != nil {
			panic(err)
		}

		// Service1 posts a 'Create' to Service2
		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
		)

		createID, err := service1.Outbox().Post(create)
		require.NoError(t, err)
		require.NotNil(t, createID)

		time.Sleep(500 * time.Millisecond)

		it, err := store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, create.ID()))

		it, err = store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, create.ID()))

		require.NotEmpty(t, subscriber2.Activities())
		require.NotEmpty(t, mockProviders2.anchorCredentialHandler.AnchorCred(anchorCredID.String()))

		// Service3 should have received an 'Announce' activity from Service2
		it, err = store3.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service3IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)

		for _, a := range activities {
			if a.Type().Is(vocab.TypeAnnounce) {
				require.Equal(t, service2IRI.String(), a.Actor().String())
			}
		}
	})
}

func TestService_Offer(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	service2, store2, publicKey2, mockProviders2 := newServiceWithMocks(t, "/services/service2", service2IRI)

	mockProviders2.witnessHandler.WithProof([]byte(proof))

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	//nolint:dogsled
	service3, _, _, _ := newServiceWithMocks(t, "/services/service3", service3IRI)

	stop3 := startHTTPServer(t, ":8303", service3.InboxHTTPHandler())
	defer stop3()

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))
	actor2 := aptestutil.NewMockService(service2IRI, aptestutil.WithPublicKey(publicKey2))

	mockProviders1.actorRetriever.WithPublicKey(publicKey2).WithActor(actor2)
	mockProviders2.actorRetriever.WithPublicKey(publicKey1).WithActor(actor1)

	require.NoError(t, store1.PutActor(actor2))
	require.NoError(t, store2.PutActor(actor1))
	require.NoError(t, store2.AddReference(spi.Witnessing, service2IRI, service1IRI))

	service1.Start()
	service2.Start()
	service3.Start()

	defer service1.Stop()
	defer service2.Stop()
	defer service3.Stop()

	t.Run("Offer", func(t *testing.T) {
		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		activityID, err := service1.Outbox().Post(offer)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(500 * time.Millisecond)

		it, err := store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, offer.ID()))

		it, err = store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, offer.ID()))

		require.NotEmpty(t, subscriber2.Activities())
		require.NotEmpty(t, mockProviders2.witnessHandler.AnchorCreds())
		require.NotNil(t, mockProviders1.proofHandler.Proof(obj.ID().String()))

		rit, err := store2.QueryReferences(spi.Liked, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		liked, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, liked)

		rit, err = store1.QueryReferences(spi.Like, spi.NewCriteria(spi.WithObjectIRI(service1IRI)))
		require.NoError(t, err)

		likes, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, likes)
	})
}

func TestService_InviteWitness(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8401/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8402/services/service2")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

	defer service1.Stop()

	service2, store2, publicKey2, mockProviders2 := newServiceWithMocks(t, "/services/service2", service2IRI)

	defer service2.Stop()

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))
	actor2 := aptestutil.NewMockService(service2IRI, aptestutil.WithPublicKey(publicKey2))

	require.NoError(t, store1.PutActor(actor2))
	require.NoError(t, store2.PutActor(actor1))

	mockProviders1.actorRetriever.WithPublicKey(publicKey2).WithActor(actor2)
	mockProviders2.actorRetriever.WithPublicKey(publicKey1).WithActor(actor1)

	stop1 := startHTTPServer(t, ":8401", service1.InboxHTTPHandler())
	defer stop1()

	stop2 := startHTTPServer(t, ":8402", service2.InboxHTTPHandler())
	defer stop2()

	service1.Start()
	service2.Start()

	defer service1.Stop()
	defer service2.Stop()

	t.Run("Accept", func(t *testing.T) {
		mockProviders2.witnessInvitationAuth.WithAccept()

		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		)

		activityID, err := service1.Outbox().Post(inviteWitness)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		it, err := store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, inviteWitness.ID()))

		it, err = store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, inviteWitness.ID()))

		rit, err := store1.QueryReferences(spi.Witness, spi.NewCriteria(spi.WithObjectIRI(service1IRI)))
		require.NoError(t, err)

		witnesses, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, witnesses)
		require.Truef(t, containsIRI(witnesses, service2IRI), "expecting %s to be a witness of %s", service2IRI, service1IRI)

		rit, err = store2.QueryReferences(spi.Witnessing, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		witnessing, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)

		require.NotEmpty(t, witnessing)
		require.Truef(t, containsIRI(witnessing, service1IRI), "expecting %s to be witnessing %s",
			service2IRI, service1IRI)

		// Ensure we have an 'Accept' activity in our inbox
		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)

		for _, a := range activities {
			if a.Type().Is(vocab.TypeAccept) {
				acceptedInvitation := a.Object().Activity()
				require.NotNil(t, acceptedInvitation)
				require.Equal(t, inviteWitness.ID(), acceptedInvitation.ID())
			}
		}
	})

	t.Run("Reject", func(t *testing.T) {
		mockProviders1.witnessInvitationAuth.WithReject()

		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		_, err := service2.Outbox().Post(inviteWitness)
		require.NoError(t, err)

		// Wait for the message to be processed
		time.Sleep(500 * time.Millisecond)

		it, err := store2.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service2IRI),
				spi.WithReferenceType(spi.Outbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err := storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, inviteWitness.ID()))

		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)
		require.True(t, containsActivity(activities, inviteWitness.ID()))

		rit, err := store1.QueryReferences(spi.Witness, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		witnesses, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(witnesses, service1IRI), "expecting %s NOT to be a witness for %s",
			service1IRI, service2IRI)

		rit, err = store1.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(service1IRI)))
		require.NoError(t, err)

		witnessing, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(witnessing, service2IRI), "expecting %s NOT to be witnessing %s",
			service1IRI, service2IRI)

		// Ensure we have a 'Reject' activity in our inbox
		it, err = store1.QueryActivities(
			spi.NewCriteria(
				spi.WithObjectIRI(service1IRI),
				spi.WithReferenceType(spi.Inbox),
			))
		require.NoError(t, err)
		require.NotNil(t, it)

		activities, err = storeutil.ReadActivities(it, -1)
		require.NoError(t, err)

		for _, a := range activities {
			if a.Type().Is(vocab.TypeReject) {
				rejectedInvitation := a.Object().Activity()
				require.NotNil(t, rejectedInvitation)
				require.Equal(t, inviteWitness.ID(), rejectedInvitation.ID())
			}
		}
	})
}

type mockProviders struct {
	actorRetriever          *mocks.ActorRetriever
	anchorCredentialHandler *mocks.AnchorCredentialHandler
	followerAuth            *mocks.ActorAuth
	witnessInvitationAuth   *mocks.ActorAuth
	undeliverableHandler    *mocks.UndeliverableHandler
	proofHandler            *mocks.ProofHandler
	witnessHandler          *mocks.WitnessHandler
}

func newServiceWithMocks(t *testing.T, endpoint string,
	serviceIRI *url.URL) (*Service, spi.Store, *vocab.PublicKeyType, *mockProviders) {
	cfg := &Config{
		ServiceEndpoint: endpoint,
		ServiceIRI:      serviceIRI,
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	providers := &mockProviders{
		actorRetriever:          mocks.NewActorRetriever(),
		anchorCredentialHandler: mocks.NewAnchorCredentialHandler(),
		followerAuth:            mocks.NewActorAuth(),
		witnessInvitationAuth:   mocks.NewActorAuth(),
		undeliverableHandler:    mocks.NewUndeliverableHandler(),
		proofHandler:            mocks.NewProofHandler(),
		witnessHandler:          mocks.NewWitnessHandler(),
	}

	pubKeyBytes, privKey1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBytes, err := publicKeyToPEM(pubKeyBytes)
	require.NoError(t, err)

	publicKey := vocab.NewPublicKey(
		vocab.WithID(testutil.NewMockID(serviceIRI, "/keys/main-key")),
		vocab.WithOwner(cfg.ServiceIRI),
		vocab.WithPublicKeyPem(string(pemBytes)),
	)

	trnspt := transport.New(http.DefaultClient, privKey1,
		publicKey.ID.URL(),
		httpsig.NewSigner(httpsig.DefaultGetSignerConfig()),
		httpsig.NewSigner(httpsig.DefaultPostSignerConfig()),
	)

	sigVerifier := httpsig.NewVerifier(httpsig.DefaultVerifierConfig(), providers.actorRetriever)

	activityStore := memstore.New(cfg.ServiceEndpoint)

	s, err := New(cfg, activityStore, trnspt, sigVerifier,
		service.WithUndeliverableHandler(providers.undeliverableHandler),
		service.WithAnchorCredentialHandler(providers.anchorCredentialHandler),
		service.WithFollowerAuth(providers.followerAuth),
		service.WithWitnessInvitationAuth(providers.witnessInvitationAuth),
		service.WithWitness(providers.witnessHandler),
		service.WithProofHandler(providers.proofHandler),
	)
	require.NoError(t, err)

	return s, activityStore, publicKey, providers
}

func newActivityID(serviceName fmt.Stringer) *url.URL {
	return testutil.MustParseURL(fmt.Sprintf("%s/%s", serviceName, uuid.New()))
}

func newTransactionID(serviceName fmt.Stringer) *url.URL {
	return testutil.MustParseURL(fmt.Sprintf("%s/%s", serviceName, uuid.New()))
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
			return true
		}
	}

	return false
}

func startHTTPServer(t *testing.T, listenAddress string, handlers ...common.HTTPHandler) func() {
	httpServer := httpserver.New(listenAddress, "", "", "", handlers...)

	require.NoError(t, httpServer.Start())

	return func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}
}

func containsActivity(activities []*vocab.ActivityType, iri fmt.Stringer) bool {
	for _, a := range activities {
		if a.ID().String() == iri.String() {
			return true
		}
	}

	return false
}

func publicKeyToPEM(publicKey crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	block := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   keyBytes,
	}

	return pem.EncodeToMemory(&block), nil
}

const anchorCredential1 = `{
 "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
 ],
 "id": "http://sally.example.com/transactions/bafkreihwsn",
 "type": [
	"VerifiableCredential",
	"AnchorCredential"
 ],
 "issuer": "https://sally.example.com/services/orb",
 "issuanceDate": "2021-01-27T09:30:10Z",
 "credentialSubject": {
	"operationCount": 2,
	"coreIndex": "bafkreihwsn",
	"namespace": "did:orb",
	"version": "1",
	"previousAnchors": {
	  "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
	  "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
	}
 },
 "proofChain": [{}]
}`

const proof = `{
 "@context": [
   "https://w3id.org/security/v1",
   "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
 ],
 "proof": {
   "type": "JsonWebSignature2020",
   "proofPurpose": "assertionMethod",
   "created": "2021-01-27T09:30:15Z",
   "verificationMethod": "did:example:abcd#key",
   "domain": "https://witness1.example.com/ledgers/maple2021",
   "jws": "eyJ..."
 }
}`
