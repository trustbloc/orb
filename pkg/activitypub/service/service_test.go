/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
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

	service1, err := New(cfg1, store1, service.WithUndeliverableHandler(undeliverableHandler1))
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

	cfg1 := &Config{
		ServiceEndpoint: "/services/service1",
		ServiceIRI:      service1IRI,
		RetryOpts:       redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceEndpoint)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := New(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
	)
	require.NoError(t, err)

	defer service1.Stop()

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	cfg2 := &Config{
		ServiceEndpoint: "/services/service2",
		ServiceIRI:      service2IRI,
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceEndpoint)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := New(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
	)
	require.NoError(t, err)

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

	unavailableServiceIRI := testutil.MustParseURL("http://localhost:8304/services/service4")

	create := vocab.NewCreateActivity(newActivityID(service1IRI),
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithActor(service1IRI),
		vocab.WithTarget(targetProperty),
		vocab.WithContext(vocab.ContextOrb),
		vocab.WithTo(service2IRI, unavailableServiceIRI),
	)

	require.NoError(t, service1.Outbox().Post(create))

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
	require.NotEmpty(t, anchorCredHandler2.AnchorCred(anchorCredID.String()))

	ua := undeliverableHandler1.Activities()
	require.Len(t, ua, 1)
	require.Equal(t, unavailableServiceIRI.String(), ua[0].ToURL)
}

func TestService_Follow(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg1 := &Config{
		ServiceEndpoint: "/services/service1",
		ServiceIRI:      service1IRI,
		RetryOpts:       redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceEndpoint)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := New(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
	)
	require.NoError(t, err)

	defer service1.Stop()

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	cfg2 := &Config{
		ServiceEndpoint: "/services/service2",
		ServiceIRI:      service2IRI,
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceEndpoint)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := New(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
	)
	require.NoError(t, err)

	defer service2.Stop()

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
		// Add Service1 to Service2's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store2.PutActor(vocab.NewService(service1IRI)))

		followerAuth2.WithAccept()

		actorIRI := service1IRI
		targetIRI := service2IRI

		follow := vocab.NewFollowActivity(newActivityID(actorIRI),
			vocab.NewObjectProperty(vocab.WithIRI(targetIRI)),
			vocab.WithActor(actorIRI),
			vocab.WithTo(targetIRI),
		)

		require.NoError(t, service1.Outbox().Post(follow))

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

		rit, err := store1.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actorIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.NotEmpty(t, following)
		require.Truef(t, containsIRI(following, targetIRI), "expecting %s to be following %s", actorIRI, targetIRI)

		rit, err = store2.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(targetIRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)

		require.NotEmpty(t, followers)
		require.Truef(t, containsIRI(followers, actorIRI), "expecting %s to have %s as a follower", targetIRI, actorIRI)

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
		// Add Service2 to Service1's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store1.PutActor(vocab.NewService(service2IRI)))

		followerAuth1.WithReject()

		actorIRI := service2IRI
		targetIRI := service1IRI

		follow := vocab.NewFollowActivity(newActivityID(actorIRI),
			vocab.NewObjectProperty(vocab.WithIRI(targetIRI)),
			vocab.WithActor(actorIRI),
			vocab.WithTo(targetIRI),
		)

		for i := 0; i < 5; i++ {
			// Wait for the service to start
			err := service2.Outbox().Post(follow)
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

		rit, err := store1.QueryReferences(spi.Following, spi.NewCriteria(spi.WithObjectIRI(actorIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(following, targetIRI), "expecting %s NOT to be following %s", actorIRI, targetIRI)

		rit, err = store1.QueryReferences(spi.Follower, spi.NewCriteria(spi.WithObjectIRI(targetIRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(rit, -1)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(followers, actorIRI), "expecting %s NOT to have %s as a follower", targetIRI, actorIRI)

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

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg1 := &Config{
		ServiceEndpoint: "/services/service1",
		ServiceIRI:      service1IRI,
		RetryOpts:       redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceEndpoint)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	proofHandler1 := mocks.NewProofHandler()
	witness1 := mocks.NewWitnessHandler()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := New(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
		service.WithWitness(witness1),
		service.WithProofHandler(proofHandler1),
	)
	require.NoError(t, err)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	cfg2 := &Config{
		ServiceEndpoint: "/services/service2",
		ServiceIRI:      service2IRI,
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceEndpoint)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	witness2 := mocks.NewWitnessHandler()
	proofHandler2 := mocks.NewProofHandler()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := New(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
		service.WithWitness(witness2),
		service.WithProofHandler(proofHandler2),
	)
	require.NoError(t, err)

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	cfg3 := &Config{
		ServiceEndpoint: "/services/service3",
		ServiceIRI:      service3IRI,
	}

	store3 := memstore.New(cfg3.ServiceEndpoint)
	anchorCredHandler3 := mocks.NewAnchorCredentialHandler()
	followerAuth3 := mocks.NewFollowerAuth()
	witness3 := mocks.NewWitnessHandler()
	proofHandler3 := mocks.NewProofHandler()
	undeliverableHandler3 := mocks.NewUndeliverableHandler()

	service3, err := New(cfg3, store3,
		service.WithUndeliverableHandler(undeliverableHandler3),
		service.WithAnchorCredentialHandler(anchorCredHandler3),
		service.WithFollowerAuth(followerAuth3),
		service.WithWitness(witness3),
		service.WithProofHandler(proofHandler3),
	)
	require.NoError(t, err)

	stop3 := startHTTPServer(t, ":8303", service3.InboxHTTPHandler())
	defer stop3()

	subscriber3 := mocks.NewSubscriber(service3.Subscribe())

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

		announce := vocab.NewAnnounceActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service3IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, service2.Outbox().Post(announce))

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

		require.NotEmpty(t, anchorCredHandler3.AnchorCred(anchorCredID.String()))
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

		announce := vocab.NewAnnounceActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service3IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, service2.Outbox().Post(announce))

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

		require.NotEmpty(t, anchorCredHandler3.AnchorCred(anchorCredID.String()))
	})

	t.Run("Create and announce", func(t *testing.T) {
		// Service3 requests to follow Service2

		// Add Service3 to Service2's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store2.PutActor(vocab.NewService(service3IRI)))

		followerAuth2.WithAccept()

		follow := vocab.NewFollowActivity(newActivityID(service3IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, service1.Outbox().Post(follow))

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
		create := vocab.NewCreateActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, service1.Outbox().Post(create))

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
		require.NotEmpty(t, anchorCredHandler2.AnchorCred(anchorCredID.String()))

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

	cfg1 := &Config{
		ServiceEndpoint: "/services/service1",
		ServiceIRI:      service1IRI,
		RetryOpts:       redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceEndpoint)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	proofHandler1 := mocks.NewProofHandler()
	witness1 := mocks.NewWitnessHandler()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := New(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
		service.WithWitness(witness1),
		service.WithProofHandler(proofHandler1),
	)
	require.NoError(t, err)

	stop1 := startHTTPServer(t, ":8301", service1.InboxHTTPHandler())
	defer stop1()

	cfg2 := &Config{
		ServiceEndpoint: "/services/service2",
		ServiceIRI:      service2IRI,
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceEndpoint)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	witness2 := mocks.NewWitnessHandler().WithProof([]byte(proof))
	proofHandler2 := mocks.NewProofHandler()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := New(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
		service.WithWitness(witness2),
		service.WithProofHandler(proofHandler2),
	)
	require.NoError(t, err)

	stop2 := startHTTPServer(t, ":8302", service2.InboxHTTPHandler())
	defer stop2()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	cfg3 := &Config{
		ServiceEndpoint: "/services/service3",
		ServiceIRI:      service3IRI,
	}

	store3 := memstore.New(cfg3.ServiceEndpoint)
	anchorCredHandler3 := mocks.NewAnchorCredentialHandler()
	followerAuth3 := mocks.NewFollowerAuth()
	witness3 := mocks.NewWitnessHandler()
	proofHandler3 := mocks.NewProofHandler()
	undeliverableHandler3 := mocks.NewUndeliverableHandler()

	service3, err := New(cfg3, store3,
		service.WithUndeliverableHandler(undeliverableHandler3),
		service.WithAnchorCredentialHandler(anchorCredHandler3),
		service.WithFollowerAuth(followerAuth3),
		service.WithWitness(witness3),
		service.WithProofHandler(proofHandler3),
	)
	require.NoError(t, err)

	stop3 := startHTTPServer(t, ":8303", service3.InboxHTTPHandler())
	defer stop3()

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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		require.NoError(t, service1.Outbox().Post(offer))

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
		require.NotEmpty(t, witness2.AnchorCreds())
		require.NotNil(t, proofHandler1.Proof(obj.ID().String()))

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

const anchorCredential1 = `{
 "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/Context/orb-v1.json"
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
