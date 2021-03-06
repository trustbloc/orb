/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestNewService(t *testing.T) {
	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ListenAddress: ":8311",
		PubSubFactory: func(serviceName string) PubSub {
			return mocks.NewPubSub()
		},
	}

	store1 := memstore.New(cfg1.ServiceName)
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1, service.WithUndeliverableHandler(undeliverableHandler1))
	require.NoError(t, err)

	service1.Start()

	require.Equal(t, service.StateStarted, service1.State())

	service1.Stop()

	require.Equal(t, service.StateStopped, service1.State())
}

func TestService_Create(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ServiceIRI:    service1IRI,
		ListenAddress: ":8301",
		RetryOpts:     redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceName)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
	)
	require.NoError(t, err)

	defer service1.Stop()

	cfg2 := &Config{
		ServiceName:   "/services/service2",
		ServiceIRI:    service2IRI,
		ListenAddress: ":8302",
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceName)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := NewService(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
	)
	require.NoError(t, err)

	defer service2.Stop()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	service1.Start()

	// delay the start of Service2 to test redelivery
	go func() {
		time.Sleep(50 * time.Millisecond)
		service2.Start()
	}()

	defer service1.Stop()
	defer service2.Stop()

	const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

	targetProperty := vocab.NewObjectProperty(vocab.WithObject(
		vocab.NewObject(
			vocab.WithID(cid),
			vocab.WithType(vocab.TypeCAS),
		),
	))

	obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
	if err != nil {
		panic(err)
	}

	unavailableServiceIRI := mustParseURL("http://localhost:8304/services/service4")

	create := vocab.NewCreateActivity(newActivityID(service1IRI),
		vocab.NewObjectProperty(vocab.WithObject(obj)),
		vocab.WithActor(service1IRI),
		vocab.WithTarget(targetProperty),
		vocab.WithContext(vocab.ContextOrb),
		vocab.WithTo(service2IRI, unavailableServiceIRI),
	)

	require.NoError(t, service1.Outbox().Post(create))

	time.Sleep(1500 * time.Millisecond)

	activity, err := store1.GetActivity(spi.Outbox, create.ID())
	require.NoError(t, err)
	require.NotNil(t, activity)
	require.Equal(t, create.ID(), activity.ID())

	activity, err = store2.GetActivity(spi.Inbox, create.ID())
	require.NoError(t, err)
	require.NotNil(t, activity)
	require.Equal(t, create.ID(), activity.ID())
	require.NotEmpty(t, subscriber2.Activities())
	require.NotEmpty(t, anchorCredHandler2.AnchorCred(cid))

	ua := undeliverableHandler1.Activities()
	require.Len(t, ua, 1)
	require.Equal(t, unavailableServiceIRI.String(), ua[0].ToURL)
}

func TestService_Follow(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ServiceIRI:    service1IRI,
		ListenAddress: ":8301",
		RetryOpts:     redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceName)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
	)
	require.NoError(t, err)

	defer service1.Stop()

	cfg2 := &Config{
		ServiceName:   "/services/service2",
		ServiceIRI:    service2IRI,
		ListenAddress: ":8302",
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceName)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := NewService(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
	)
	require.NoError(t, err)

	defer service2.Stop()

	service1.Start()

	// delay the start of Service2 to test redelivery
	go func() {
		time.Sleep(50 * time.Millisecond)
		service2.Start()
	}()

	defer service1.Stop()
	defer service2.Stop()

	t.Run("Follow - Accept", func(t *testing.T) {
		// Add Service1 to Service2's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store2.PutActor(vocab.NewService(service1IRI.String())))

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

		activity, err := store1.GetActivity(spi.Outbox, follow.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, follow.ID(), activity.ID())

		activity, err = store2.GetActivity(spi.Inbox, follow.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, follow.ID(), activity.ID())

		following, err := store1.GetReferences(spi.Following, actorIRI)
		require.NoError(t, err)
		require.NotEmpty(t, following)
		require.Truef(t, containsIRI(following, targetIRI), "expecting %s to be following %s", actorIRI, targetIRI)

		followers, err := store2.GetReferences(spi.Follower, targetIRI)
		require.NoError(t, err)
		require.NotEmpty(t, followers)
		require.Truef(t, containsIRI(followers, actorIRI), "expecting %s to have %s as a follower", targetIRI, actorIRI)

		// Ensure we have an 'Accept' activity in our inbox
		it, err := store1.QueryActivities(spi.Inbox, spi.NewCriteria(spi.WithType(vocab.TypeAccept)))
		require.NoError(t, err)
		require.NotNil(t, it)

		accept, err := it.Next()
		require.NoError(t, err)
		require.True(t, accept.Type().Is(vocab.TypeAccept))

		acceptedFollow := accept.Object().Activity()
		require.NotNil(t, acceptedFollow)
		require.Equal(t, follow.ID(), acceptedFollow.ID())
	})

	t.Run("Follow - Reject", func(t *testing.T) {
		// Add Service2 to Service1's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store1.PutActor(vocab.NewService(service2IRI.String())))

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

		activity, err := store2.GetActivity(spi.Outbox, follow.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, follow.ID(), activity.ID())

		activity, err = store1.GetActivity(spi.Inbox, follow.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, follow.ID(), activity.ID())

		following, err := store2.GetReferences(spi.Following, actorIRI)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(following, targetIRI), "expecting %s NOT to be following %s", actorIRI, targetIRI)

		followers, err := store1.GetReferences(spi.Follower, targetIRI)
		require.NoError(t, err)
		require.Falsef(t, containsIRI(followers, actorIRI), "expecting %s NOT to have %s as a follower", targetIRI, actorIRI)

		// Ensure we have a 'Reject' activity in our inbox
		it, err := store2.QueryActivities(spi.Inbox, spi.NewCriteria(spi.WithType(vocab.TypeReject)))
		require.NoError(t, err)
		require.NotNil(t, it)

		reject, err := it.Next()
		require.NoError(t, err)

		require.True(t, reject.Type().Is(vocab.TypeReject))

		rejectedFollow := reject.Object().Activity()
		require.NotNil(t, rejectedFollow)
		require.Equal(t, follow.ID(), rejectedFollow.ID())
	})
}

func TestService_Announce(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")
	service3IRI := mustParseURL("http://localhost:8303/services/service3")

	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ServiceIRI:    service1IRI,
		ListenAddress: ":8301",
		RetryOpts:     redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceName)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	proofHandler1 := mocks.NewProofHandler()
	witness1 := mocks.NewWitnessHandler()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
		service.WithWitness(witness1),
		service.WithProofHandler(proofHandler1),
	)
	require.NoError(t, err)

	cfg2 := &Config{
		ServiceName:   "/services/service2",
		ServiceIRI:    service2IRI,
		ListenAddress: ":8302",
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceName)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	witness2 := mocks.NewWitnessHandler()
	proofHandler2 := mocks.NewProofHandler()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := NewService(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
		service.WithWitness(witness2),
		service.WithProofHandler(proofHandler2),
	)
	require.NoError(t, err)

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	cfg3 := &Config{
		ServiceName:   "/services/service3",
		ServiceIRI:    service3IRI,
		ListenAddress: ":8303",
	}

	store3 := memstore.New(cfg3.ServiceName)
	anchorCredHandler3 := mocks.NewAnchorCredentialHandler()
	followerAuth3 := mocks.NewFollowerAuth()
	witness3 := mocks.NewWitnessHandler()
	proofHandler3 := mocks.NewProofHandler()
	undeliverableHandler3 := mocks.NewUndeliverableHandler()

	service3, err := NewService(cfg3, store3,
		service.WithUndeliverableHandler(undeliverableHandler3),
		service.WithAnchorCredentialHandler(anchorCredHandler3),
		service.WithFollowerAuth(followerAuth3),
		service.WithWitness(witness3),
		service.WithProofHandler(proofHandler3),
	)
	require.NoError(t, err)

	subscriber3 := mocks.NewSubscriber(service3.Subscribe())

	service1.Start()
	service2.Start()
	service3.Start()

	defer service1.Stop()
	defer service2.Stop()
	defer service3.Stop()

	t.Run("Announce - anchor credential ref (no embedded object)", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		ref := vocab.NewAnchorCredentialReference(newActivityID(service2IRI), cid)

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

		activity, err := store2.GetActivity(spi.Outbox, announce.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, announce.ID(), activity.ID())

		activity, err = store3.GetActivity(spi.Inbox, announce.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, announce.ID(), activity.ID())

		require.NotEmpty(t, subscriber3.Activities())

		require.NotEmpty(t, anchorCredHandler3.AnchorCred(cid))
	})

	t.Run("Announce - anchor credential ref (with embedded object)", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		ref, err := vocab.NewAnchorCredentialReferenceWithDocument(newTransactionID(service2IRI),
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

		activity, err := store2.GetActivity(spi.Outbox, announce.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, announce.ID(), activity.ID())

		activity, err = store3.GetActivity(spi.Inbox, announce.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, announce.ID(), activity.ID())

		require.NotEmpty(t, subscriber3.Activities())

		require.NotEmpty(t, anchorCredHandler3.AnchorCred(cid))
	})

	t.Run("Create and announce", func(t *testing.T) {
		// Service3 requests to follow Service2

		// Add Service3 to Service2's store since we haven't implemented actor resolution yet and
		// Service2 needs to retrieve the requesting actor.
		require.NoError(t, store2.PutActor(vocab.NewService(service3IRI.String())))

		followerAuth2.WithAccept()

		follow := vocab.NewFollowActivity(newActivityID(service3IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, service1.Outbox().Post(follow))

		time.Sleep(1000 * time.Millisecond)

		followers, err := store2.GetReferences(spi.Follower, service2IRI)
		require.NoError(t, err)
		require.NotEmpty(t, followers)
		require.Truef(t, containsIRI(followers, service3IRI), "expecting %s to have %s as a follower",
			service2IRI, service3IRI)

		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3z"

		targetProperty := vocab.NewObjectProperty(vocab.WithObject(
			vocab.NewObject(
				vocab.WithID(cid),
				vocab.WithType(vocab.TypeCAS),
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

		activity, err := store1.GetActivity(spi.Outbox, create.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, create.ID(), activity.ID())

		activity, err = store2.GetActivity(spi.Inbox, create.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, create.ID(), activity.ID())
		require.NotEmpty(t, subscriber2.Activities())
		require.NotEmpty(t, anchorCredHandler2.AnchorCred(cid))

		// Service3 should have received an 'Announce' activity from Service2
		it, err := store3.QueryActivities(spi.Inbox, spi.NewCriteria(spi.WithType(vocab.TypeAnnounce)))
		require.NoError(t, err)

		announce, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, announce)
		require.Equal(t, service2IRI.String(), announce.Actor().String())
	})
}

func TestService_Offer(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")
	service3IRI := mustParseURL("http://localhost:8303/services/service3")

	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ServiceIRI:    service1IRI,
		ListenAddress: ":8301",
		RetryOpts:     redelivery.DefaultConfig(),
	}

	store1 := memstore.New(cfg1.ServiceName)
	anchorCredHandler1 := mocks.NewAnchorCredentialHandler()
	followerAuth1 := mocks.NewFollowerAuth()
	proofHandler1 := mocks.NewProofHandler()
	witness1 := mocks.NewWitnessHandler()
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
		service.WithAnchorCredentialHandler(anchorCredHandler1),
		service.WithFollowerAuth(followerAuth1),
		service.WithWitness(witness1),
		service.WithProofHandler(proofHandler1),
	)
	require.NoError(t, err)

	cfg2 := &Config{
		ServiceName:   "/services/service2",
		ServiceIRI:    service2IRI,
		ListenAddress: ":8302",
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceName)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	followerAuth2 := mocks.NewFollowerAuth()
	witness2 := mocks.NewWitnessHandler().WithProof([]byte(proof))
	proofHandler2 := mocks.NewProofHandler()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := NewService(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
		service.WithFollowerAuth(followerAuth2),
		service.WithWitness(witness2),
		service.WithProofHandler(proofHandler2),
	)
	require.NoError(t, err)

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	cfg3 := &Config{
		ServiceName:   "/services/service3",
		ServiceIRI:    service3IRI,
		ListenAddress: ":8303",
	}

	store3 := memstore.New(cfg3.ServiceName)
	anchorCredHandler3 := mocks.NewAnchorCredentialHandler()
	followerAuth3 := mocks.NewFollowerAuth()
	witness3 := mocks.NewWitnessHandler()
	proofHandler3 := mocks.NewProofHandler()
	undeliverableHandler3 := mocks.NewUndeliverableHandler()

	service3, err := NewService(cfg3, store3,
		service.WithUndeliverableHandler(undeliverableHandler3),
		service.WithAnchorCredentialHandler(anchorCredHandler3),
		service.WithFollowerAuth(followerAuth3),
		service.WithWitness(witness3),
		service.WithProofHandler(proofHandler3),
	)
	require.NoError(t, err)

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

		activity, err := store1.GetActivity(spi.Outbox, offer.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, offer.ID(), activity.ID())

		activity, err = store2.GetActivity(spi.Inbox, offer.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, offer.ID(), activity.ID())

		require.NotEmpty(t, subscriber2.Activities())
		require.NotEmpty(t, witness2.AnchorCreds())
		require.NotNil(t, proofHandler1.Proof(obj.ID()))

		liked, err := store2.GetReferences(spi.Liked, service2IRI)
		require.NoError(t, err)
		require.NotEmpty(t, liked)

		likes, err := store1.GetReferences(spi.Like, service1IRI)
		require.NoError(t, err)
		require.NotEmpty(t, likes)
	})
}

func newActivityID(serviceName fmt.Stringer) string {
	return fmt.Sprintf("%s/%s", serviceName, uuid.New())
}

func newTransactionID(serviceName fmt.Stringer) string {
	return fmt.Sprintf("%s/%s", serviceName, uuid.New())
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
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
	"anchorString": "bafkreihwsn",
	"namespace": "did:orb",
	"version": "1",
	"previousTransactions": {
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
