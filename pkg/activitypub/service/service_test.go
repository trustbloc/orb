/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"

	clientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/httpsig"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/linkset"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger"
)

//go:generate counterfeiter -o ./mocks/activityiterator.gen.go --fake-name ActivityIterator ./../client ActivityIterator

func TestNewService(t *testing.T) {
	serviceIRI := testutil.MustParseURL("http://localhost:8301/services/service1")

	cfg1 := &Config{
		ServicePath:        "/services/service1",
		ServiceIRI:         serviceIRI,
		ServiceEndpointURL: serviceIRI,
	}

	tm := &apmocks.AuthTokenMgr{}

	store1 := memstore.New(cfg1.ServicePath)

	service1, err := New(cfg1, store1, transport.Default(), &mocks.SignatureVerifier{}, mocks.NewPubSub(),
		mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, tm, &orbmocks.MetricsProvider{})
	require.NoError(t, err)
	require.NotNil(t, service1.InboxHandler())

	stop := startHTTPServer(t, ":8311", service1.InboxHTTPHandler())
	defer stop()

	service1.Start()

	require.Equal(t, lifecycle.StateStarted, service1.State())

	service1.Stop()

	require.Equal(t, lifecycle.StateStopped, service1.State())
}

func TestService_Create(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	unavailableServiceIRI := testutil.MustParseURL("http://localhost:8304/services/service4")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

	actor1 := aptestutil.NewMockService(service1IRI, aptestutil.WithPublicKey(publicKey1))

	mockProviders1.actorRetriever.WithActor(actor1)
	mockProviders1.actorRetriever.WithActor(aptestutil.NewMockService(service2IRI))
	mockProviders1.actorRetriever.WithActor(aptestutil.NewMockService(unavailableServiceIRI))

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

	anchorEvent := aptestutil.NewMockAnchorEvent(t, aptestutil.NewMockAnchorLink(t))

	create := vocab.NewCreateActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)),
		vocab.WithTo(service2IRI, unavailableServiceIRI),
	)

	createID, err := service1.Outbox().Post(context.Background(), create)
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

	_, exists := mockProviders2.anchorEventHandler.AnchorEvent(anchorEvent.URL()[0].String())
	require.True(t, exists)
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

	mockProviders1.actorRetriever.WithActor(actor2)
	mockProviders2.actorRetriever.WithActor(actor1)

	mockProviders1.actorRetriever.WithPublicKey(publicKey2).WithActor(actor2)
	mockProviders2.actorRetriever.WithPublicKey(publicKey1).WithActor(actor1)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	service1.Start()
	service2.Start()

	defer service1.Stop()
	defer service2.Stop()

	t.Run("Follow - Accept", func(t *testing.T) {
		mockProviders2.followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		)

		activityID, err := service1.Outbox().Post(context.Background(), follow)
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
			_, err := service2.Outbox().Post(context.Background(), follow)
			if err == nil {
				break
			}

			if !errors.Is(err, lifecycle.ErrNotStarted) {
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

//nolint:maintidx
func TestService_Announce(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)
	log.SetLevel("activitypub_service", log.DEBUG)
	log.SetLevel("activitypub_client", log.DEBUG)
	log.SetLevel("activitypub_httpsig", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	service1, store1, publicKey1, mockProviders1 := newServiceWithMocks(t, "/services/service1", service1IRI)

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

	mockProviders1.actorRetriever.
		WithPublicKey(publicKey2).WithActor(actor2)

	mockProviders2.actorRetriever.
		WithPublicKey(publicKey1).WithActor(actor1).
		WithPublicKey(publicKey3).WithActor(actor3)

	mockProviders3.actorRetriever.
		WithPublicKey(publicKey2).WithActor(actor2)

	service1.Start()
	service2.Start()
	service3.Start()

	defer service1.Stop()
	defer service2.Stop()
	defer service3.Stop()

	t.Run("Announce - anchor credential ref (no embedded object)", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEvent(t, aptestutil.NewMockAnchorLink(t))

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
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

		activityID, err := service2.Outbox().Post(context.Background(), announce)
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

		_, exists := mockProviders3.anchorEventHandler.AnchorEvent(anchorEvent.URL()[0].String())
		require.True(t, exists)
	})

	t.Run("Announce - anchor credential ref (with embedded object)", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEventRef(t)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
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

		activityID, err := service2.Outbox().Post(context.Background(), announce)
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

		_, exists := mockProviders3.anchorEventHandler.AnchorEvent(anchorEvent.URL()[0].String())
		require.True(t, exists)
	})

	t.Run("Create and announce", func(t *testing.T) {
		// Service3 requests to follow Service2; Service1 requests to follow Service3

		mockProviders2.followerAuth.WithAccept()
		mockProviders3.followerAuth.WithAccept()

		activityID, err := service3.Outbox().Post(context.Background(), vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		))
		require.NoError(t, err)
		require.NotNil(t, activityID)

		activityID, err = service1.Outbox().Post(context.Background(), vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		))
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(2000 * time.Millisecond)

		rit, err := store2.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Truef(t, containsIRI(followers, service1IRI), "expecting %s to have %s as a follower",
			service2IRI, service1IRI)
		require.Truef(t, containsIRI(followers, service3IRI), "expecting %s to have %s as a follower",
			service2IRI, service3IRI)

		anchorEvent := aptestutil.NewMockAnchorEvent(t, aptestutil.NewMockAnchorLink(t))

		// Service1 posts a 'Create' to Service2
		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)),
			vocab.WithContext(vocab.ContextActivityAnchors),
			vocab.WithTo(service2IRI),
		)

		createID, err := service1.Outbox().Post(context.Background(), create)
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

		_, exists := mockProviders2.anchorEventHandler.AnchorEvent(anchorEvent.URL()[0].String())
		require.True(t, exists)

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

	require.NoError(t, store2.AddReference(spi.Witnessing, service2IRI, service1IRI))

	service1.Start()
	service2.Start()
	service3.Start()

	defer service1.Stop()
	defer service2.Stop()
	defer service3.Stop()

	t.Run("Offer", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorLink := aptestutil.NewMockAnchorLink(t)

		anchorLinksetDoc, err := vocab.MarshalToDoc(linkset.New(anchorLink))
		require.NoError(t, err)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithDocument(anchorLinksetDoc)),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		activityID, err := service1.Outbox().Post(context.Background(), offer)
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
		require.NotNil(t, mockProviders1.proofHandler.Proof(anchorLink.Anchor().String()))
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

		inviteWitness := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithTo(service2IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service2IRI))),
		)

		activityID, err := service1.Outbox().Post(context.Background(), inviteWitness)
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

		inviteWitness := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		_, err := service2.Outbox().Post(context.Background(), inviteWitness)
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
	actorRetriever        *mocks.ActivityPubClient
	anchorEventHandler    *mocks.AnchorEventHandler
	followerAuth          *mocks.ActorAuth
	witnessInvitationAuth *mocks.ActorAuth
	proofHandler          *mocks.ProofHandler
	witnessHandler        *mocks.WitnessHandler
	anchorEventAckHandler *mocks.AnchorEventAcknowledgementHandler
	acceptFollowHandler   *mocks.AcceptFollowHandler
	undoFollowHandler     *mocks.UndoFollowHandler
}

func newServiceWithMocks(t *testing.T, endpoint string, serviceIRI *url.URL) (*Service, spi.Store, *vocab.PublicKeyType, *mockProviders) {
	t.Helper()

	const kmsKey1 = "123456"

	cfg := &Config{
		ServicePath:        endpoint,
		ServiceIRI:         serviceIRI,
		ServiceEndpointURL: serviceIRI,
	}

	providers := &mockProviders{
		actorRetriever:        mocks.NewActivitPubClient(),
		anchorEventHandler:    mocks.NewAnchorEventHandler(),
		followerAuth:          mocks.NewActorAuth(),
		witnessInvitationAuth: mocks.NewActorAuth(),
		proofHandler:          mocks.NewProofHandler(),
		witnessHandler:        mocks.NewWitnessHandler(),
		anchorEventAckHandler: mocks.NewAnchorEventAcknowledgementHandler(),
		acceptFollowHandler:   mocks.NewAcceptFollowHandler(),
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "P-256",
		Bytes: pubKey,
	})

	publicKey := vocab.NewPublicKey(
		vocab.WithID(testutil.NewMockID(serviceIRI, "/keys/main-key")),
		vocab.WithOwner(cfg.ServiceIRI),
		vocab.WithPublicKeyPem(string(pemBytes)),
	)

	cr := &mockcrypto.Crypto{SignFn: func(bytes []byte, i interface{}) ([]byte, error) {
		s := ecsigner.New(privKey, "ES256", uuid.NewString())

		return s.Sign(bytes)
	}}

	km := &mockkms.KeyManager{}

	clientAuthTokenMgr := &clientmocks.AuthTokenMgr{}
	clientAuthTokenMgr.IsAuthRequiredReturns(true, nil)

	serverAuthTokenMgr := &apmocks.AuthTokenMgr{}
	serverAuthTokenMgr.RequiredAuthTokensReturns([]string{"admin"}, nil)

	trnspt := transport.New(http.DefaultClient,
		publicKey.ID(),
		httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), cr, km, kmsKey1),
		httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), cr, km, kmsKey1),
		clientAuthTokenMgr,
	)

	activityStore := memstore.New(cfg.ServicePath)

	s, err := New(cfg, activityStore, trnspt, httpsig.NewVerifier(providers.actorRetriever, cr, km),
		mocks.NewPubSub(), providers.actorRetriever, &mocks.WebFingerResolver{},
		serverAuthTokenMgr, &orbmocks.MetricsProvider{},
		service.WithAnchorEventHandler(providers.anchorEventHandler),
		service.WithFollowAuth(providers.followerAuth),
		service.WithInviteWitnessAuth(providers.witnessInvitationAuth),
		service.WithWitness(providers.witnessHandler),
		service.WithProofHandler(providers.proofHandler),
		service.WithAnchorEventAcknowledgementHandler(providers.anchorEventAckHandler),
		service.WithAcceptFollowHandler(providers.acceptFollowHandler),
		service.WithUndoFollowHandler(providers.undoFollowHandler),
	)
	require.NoError(t, err)

	return s, activityStore, publicKey, providers
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
	t.Helper()

	httpServer := httpserver.New(listenAddress, httpserver.WithHandlers(handlers...))

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

const proof = `{
 "@context": [
   "https://w3id.org/security/v1",
   "https://w3id.org/security/suites/jws-2020/v1"
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
