/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	storemocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const cid = "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

var (
	host1      = testutil.MustParseURL("https://sally.example.com")
	anchCredID = testutil.NewMockID(host1, "/transactions/bafkreihwsn")
)

func TestNewInbox(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	require.Equal(t, spi.StateNotStarted, h.State())

	h.Start()

	require.Equal(t, spi.StateStarted, h.State())

	h.Stop()

	require.Equal(t, spi.StateStopped, h.State())
}

func TestNewOutbox(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := NewOutbox(cfg, &mocks.ActivityStore{}, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	require.Equal(t, spi.StateNotStarted, h.State())

	h.Start()

	require.Equal(t, spi.StateStarted, h.State())

	h.Stop()

	require.Equal(t, spi.StateStopped, h.State())
}

func TestHandler_HandleUnsupportedActivity(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
	}

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	t.Run("Unsupported activity", func(t *testing.T) {
		activity := &vocab.ActivityType{
			ObjectType: vocab.NewObject(vocab.WithType(vocab.Type("unsupported_type"))),
		}
		err := h.HandleActivity(activity)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported activity type")
	})
}

func TestHandler_HandleCreateActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	activityStore := memstore.New(cfg.ServiceName)
	ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

	require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
	require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

	h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{}, spi.WithAnchorCredentialHandler(anchorCredHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Anchor credential", func(t *testing.T) {
		targetProperty := vocab.NewObjectProperty(vocab.WithObject(
			vocab.NewObject(
				vocab.WithID(anchCredID),
				vocab.WithCID(cid),
				vocab.WithType(vocab.TypeContentAddressedStorage),
			),
		))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		if err != nil {
			panic(err)
		}

		published := time.Now()

		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, subscriber.Activity(create.ID()))

			require.NotNil(t, anchorCredHandler.AnchorCred(anchCredID.String()))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchCredID)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Handler error", func(t *testing.T) {
			errExpected := fmt.Errorf("injected anchor cred handler error")

			anchorCredHandler.WithError(errExpected)
			defer func() { anchorCredHandler.WithError(nil) }()

			require.True(t, errors.Is(h.HandleActivity(create), errExpected))
		})
	})

	t.Run("Anchor credential reference", func(t *testing.T) {
		refID := testutil.MustParseURL("https://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvaty")

		published := time.Now()

		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(
					vocab.NewAnchorCredentialReference(refID, anchCredID, cid),
				),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, subscriber.Activity(create.ID()))

			require.NotNil(t, anchorCredHandler.AnchorCred(anchCredID.String()))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchCredID)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Handler error", func(t *testing.T) {
			errExpected := fmt.Errorf("injected anchor cred handler error")

			anchorCredHandler.WithError(errExpected)
			defer func() { anchorCredHandler.WithError(nil) }()

			require.True(t, errors.Is(h.HandleActivity(create), errExpected))
		})
	})

	t.Run("Unsupported object type", func(t *testing.T) {
		published := time.Now()

		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeService)))),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type in 'Create' activity")
	})
}

func TestHandler_HandleFollowActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")
	service4IRI := testutil.MustParseURL("http://localhost:8304/services/service4")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	// Add Service2 & Service3 to Service1's store since we haven't implemented actor resolution yet and
	// Service1 needs to retrieve the requesting actors.
	require.NoError(t, as.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, as.PutActor(vocab.NewService(service3IRI)))

	followerAuth := mocks.NewActorAuth()

	httpClient := &apmocks.HTTPTransport{}
	httpClient.GetReturns(nil, client.ErrNotFound)

	h := NewInbox(cfg, as, ob, httpClient, spi.WithFollowerAuth(followerAuth))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept", func(t *testing.T) {
		followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(follow.ID()))

		it, err := h.store.QueryReferences(store.Follower, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		followers, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(followers, service2IRI))
		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 1)

		// Post another follow. Should reply with accept since it's already a follower.
		follow = vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(follow.ID()))

		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 2)
	})

	t.Run("Reject", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		followerAuth.WithReject()

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(follow))

			time.Sleep(50 * time.Millisecond)

			require.Nil(t, subscriber.Activity(follow.ID()))

			it, err := h.store.QueryReferences(store.Follower, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.False(t, containsIRI(followers, service3IRI))
			require.Len(t, ob.Activities().QueryByType(vocab.TypeReject), 1)
		})
	})

	t.Run("No actor in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no actor specified")
	})

	t.Run("No object IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no IRI specified in 'object' field")
	})

	t.Run("Object IRI does not match target service IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "this service is not the target object for the 'Undo'")
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service4IRI)),
			vocab.WithActor(service4IRI),
			vocab.WithTo(service1IRI),
		)

		require.True(t, errors.Is(h.HandleActivity(follow), client.ErrNotFound))
	})

	t.Run("AuthorizeActor error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected authorize error")

		followerAuth.WithError(errExpected)

		defer func() {
			followerAuth.WithError(nil)
		}()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestHandler_HandleInviteWitnessActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")
	service4IRI := testutil.MustParseURL("http://localhost:8304/services/service4")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	require.NoError(t, as.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, as.PutActor(vocab.NewService(service3IRI)))

	witnessInvitationAuth := mocks.NewActorAuth()

	httpClient := &apmocks.HTTPTransport{}
	httpClient.GetReturns(nil, client.ErrNotFound)

	h := NewInbox(cfg, as, ob, httpClient, spi.WithWitnessInvitationAuth(witnessInvitationAuth))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept", func(t *testing.T) {
		witnessInvitationAuth.WithAccept()

		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(inviteWitness))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(inviteWitness.ID()))

		it, err := h.store.QueryReferences(store.Witnessing, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		witnesses, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(witnesses, service2IRI))
		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 1)

		// Post another invitation. Should reply with accept since it's already a inviteWitness.
		inviteWitness = vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(inviteWitness))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(inviteWitness.ID()))

		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 2)
	})

	t.Run("Reject", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		witnessInvitationAuth.WithReject()

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(inviteWitness))

			time.Sleep(50 * time.Millisecond)

			require.Nil(t, subscriber.Activity(inviteWitness.ID()))

			it, err := h.store.QueryReferences(store.Witnessing, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
			require.NoError(t, err)

			witnesses, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.False(t, containsIRI(witnesses, service3IRI))
			require.Len(t, ob.Activities().QueryByType(vocab.TypeReject), 1)
		})
	})

	t.Run("No actor in Witness activity", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(inviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no actor specified")
	})

	t.Run("No object IRI in Witness activity", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(inviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no IRI specified in 'object' field")
	})

	t.Run("Object IRI does not match target service IRI in Witness activity", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(inviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), "this service is not the target object for the 'Undo'")
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service4IRI)),
			vocab.WithActor(service4IRI),
			vocab.WithTo(service1IRI),
		)

		require.True(t, errors.Is(h.HandleActivity(inviteWitness), client.ErrNotFound))
	})

	t.Run("AuthorizeWitness error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected authorize error")

		witnessInvitationAuth.WithError(errExpected)

		defer func() {
			witnessInvitationAuth.WithError(nil)
		}()

		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(inviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestHandler_HandleAcceptActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := NewInbox(cfg, as, ob, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept Follow -> Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(accept))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(accept.ID()))

		it, err := h.store.QueryReferences(store.Following, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(following, service1IRI))

		// Post another accept activity with the same actor.
		err = h.HandleActivity(accept)
		require.Error(t, err)
		require.Contains(t, err.Error(), "already in the 'following' collection")
	})

	t.Run("Accept Witness -> Success", func(t *testing.T) {
		inviteWitness := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(inviteWitness)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(accept))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(accept.ID()))

		it, err := h.store.QueryReferences(store.Witness, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		witnesses, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(witnesses, service1IRI))

		// Post another accept activity with the same actor.
		err = h.HandleActivity(accept)
		require.Error(t, err)
		require.Contains(t, err.Error(), "already in the 'witnesses' collection")
	})

	t.Run("No actor in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept), "no actor specified in 'Accept' activity")
	})

	t.Run("No activity specified in 'object' field", func(t *testing.T) {
		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no activity specified in the 'object' field of the 'Accept' activity")
	})

	t.Run("Unsupported activity type", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"unsupported activity type [Announce] in the 'object' field of the 'Accept' activity")
	})

	t.Run("No actor specified in the activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no actor specified in the object of the 'Accept' activity")
	})

	t.Run("Actor in object does not match target service IRI in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"the actor in the object of the 'Accept' activity is not this service")
	})
}

func TestHandler_HandleAcceptActivityError(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := &mocks.ActivityStore{}

	h := NewInbox(cfg, as, ob, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	follow := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	acceptFollow := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(follow)),
		vocab.WithID(newActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
	)

	inviteWitness := vocab.NewInviteWitnessActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	acceptInviteWitness := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(inviteWitness)),
		vocab.WithID(newActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
	)

	t.Run("Accept Follow query error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(nil, errExpected)

		err := h.HandleActivity(acceptFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept Follow AddReference error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(&storemocks.ReferenceIterator{}, nil)
		as.AddReferenceReturns(errExpected)

		err := h.HandleActivity(acceptFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept InviteWitness query error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(nil, errExpected)

		err := h.HandleActivity(acceptInviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept InviteWitness AddReference error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(&storemocks.ReferenceIterator{}, nil)
		as.AddReferenceReturns(errExpected)

		err := h.HandleActivity(acceptInviteWitness)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestHandler_HandleRejectActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := NewInbox(cfg, as, ob, &apmocks.HTTPTransport{})
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Reject Follow -> Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(reject))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(reject.ID()))

		it, err := h.store.QueryReferences(store.Following, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.True(t, !containsIRI(following, service1IRI))
	})

	t.Run("Reject Witness -> Success", func(t *testing.T) {
		follow := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(reject))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(reject.ID()))

		it, err := h.store.QueryReferences(store.Witness, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.True(t, !containsIRI(following, service1IRI))
	})

	t.Run("No actor in Reject activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject), "no actor specified in 'Reject' activity")
	})

	t.Run("No Follow activity specified in 'object' field", func(t *testing.T) {
		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no activity specified in the 'object' field of the 'Reject' activity")
	})

	t.Run("Unsupported activity type", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"unsupported activity type [Announce] in the 'object' field of the 'Accept' activity")
	})

	t.Run("No actor specified in the activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no actor specified in the object of the 'Reject' activity")
	})

	t.Run("Actor does not match target service IRI in Reject activity", func(t *testing.T) {
		follow := vocab.NewInviteWitnessActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"the actor in the object of the 'Reject' activity is not this service")
	})
}

func TestHandler_HandleAnnounceActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &apmocks.HTTPTransport{},
		spi.WithAnchorCredentialHandler(anchorCredHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Anchor credential ref - collection (no embedded object)", func(t *testing.T) {
		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), anchCredID, cid)

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
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))
	})

	t.Run("Anchor credential ref - ordered collection (no embedded object)", func(t *testing.T) {
		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), anchCredID, cid)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithOrderedCollection(
					vocab.NewOrderedCollection(items),
				),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))
	})

	t.Run("Anchor credential ref (with embedded object)", func(t *testing.T) {
		ref, err := vocab.NewAnchorCredentialReferenceWithDocument(newTransactionID(service1IRI),
			anchCredID, cid, vocab.MustUnmarshalToDoc([]byte(anchorCredential1)),
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
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))
	})

	t.Run("Anchor credential ref - collection - unsupported object type", func(t *testing.T) {
		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting 'AnchorCredentialReference' type")
	})

	t.Run("Anchor credential ref - ordered collection - unsupported object type", func(t *testing.T) {
		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithOrderedCollection(
					vocab.NewOrderedCollection(items),
				),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting 'AnchorCredentialReference' type")
	})

	t.Run("Anchor credential ref - unsupported object type", func(t *testing.T) {
		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type for 'Announce'")
	})
}

func TestHandler_HandleOfferActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))
	witness := mocks.NewWitnessHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), ob, &apmocks.HTTPTransport{}, spi.WithWitness(witness))
	require.NotNil(t, h)

	require.NoError(t, h.store.AddReference(store.Witnessing, h.ServiceIRI, service1IRI))

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Success", func(t *testing.T) {
		witness.WithProof([]byte(proof))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		require.NoError(t, h.HandleActivity(offer))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(offer.ID()))
		require.Len(t, witness.AnchorCreds(), 1)

		it, err := h.store.QueryReferences(store.Liked, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		liked, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, liked)
	})

	t.Run("No response from witness -> error", func(t *testing.T) {
		witness.WithProof(nil)

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err = h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to unmarshal proof")
	})

	t.Run("Witness error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected witness error")

		witness.WithError(errExpected)
		defer witness.WithError(nil)

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		require.True(t, errors.Is(h.HandleActivity(offer), errExpected))
	})

	t.Run("No start time", func(t *testing.T) {
		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		endTime := time.Now().Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithEndTime(&endTime),
		)

		err = h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "startTime is required")
	})

	t.Run("No end time", func(t *testing.T) {
		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
		)

		err = h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "endTime is required")
	})

	t.Run("Invalid object type", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeAnnounce)))),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type in Offer activity Announce")
	})

	t.Run("No object", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object is required")
	})

	t.Run("Storage error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		activityStore := &mocks.ActivityStore{}
		activityStore.QueryReferencesReturns(nil, errExpected)

		handler := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{}, spi.WithWitness(witness))
		require.NotNil(t, handler)

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		require.True(t, errors.Is(handler.HandleActivity(offer), errExpected))
	})

	t.Run("Not witnessing actor", func(t *testing.T) {
		witness.WithProof([]byte(proof))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err = h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not in the 'witnessing' collection")
	})
}

func TestHandler_HandleLikeActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	proofHandler := mocks.NewProofHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), &mocks.Outbox{}, &apmocks.HTTPTransport{},
		spi.WithProofHandler(proofHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Success", func(t *testing.T) {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		require.NoError(t, h.HandleActivity(like))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(like.ID()))

		require.NotEmpty(t, proofHandler.Proof(anchorCredID.String()))

		it, err := h.store.QueryReferences(store.Like, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		likes, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, likes)
	})

	t.Run("HandleProof error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected witness error")

		proofHandler.WithError(errExpected)
		defer proofHandler.WithError(nil)

		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		require.True(t, errors.Is(h.HandleActivity(like), errExpected))
	})

	t.Run("No start time", func(t *testing.T) {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		err = h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), "startTime is required")
	})

	t.Run("No end time", func(t *testing.T) {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		err = h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), "endTime is required")
	})

	t.Run("No object IRI", func(t *testing.T) {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		err = h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object is required")
	})

	t.Run("No result", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(newActivityID(h.ServiceIRI)),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err := h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), "result is required")
	})
}

func TestHandler_HandleUndoFollowActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	ibHandler, obHandler, ibSubscriber, obSubscriber, stop := startInboxOutboxWithMocks(t, service1IRI, service2IRI)
	defer stop()

	follow := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followNoIRI := vocab.NewFollowActivity(
		vocab.NewObjectProperty(),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followIRINotLocalService := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followActorNotLocalService := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service3IRI),
		vocab.WithTo(service1IRI),
	)

	unsupported := vocab.NewLikeActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(ibHandler.ServiceIRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	require.NoError(t, obHandler.store.AddActivity(follow))
	require.NoError(t, obHandler.store.AddActivity(followNoIRI))
	require.NoError(t, obHandler.store.AddActivity(followActorNotLocalService))

	require.NoError(t, ibHandler.store.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, ibHandler.store.AddActivity(follow))
	require.NoError(t, ibHandler.store.AddActivity(followNoIRI))
	require.NoError(t, ibHandler.store.AddActivity(followIRINotLocalService))
	require.NoError(t, ibHandler.store.AddActivity(unsupported))

	t.Run("No actor in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, ibHandler.HandleActivity(undo), "no actor specified in 'Undo' activity")
	})

	t.Run("No object IRI in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, ibHandler.HandleActivity(undo),
			"no IRI specified in 'object' field of the 'Undo' activity")
	})

	t.Run("Activity not found in storage", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(newActivityID(service3IRI))),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), store.ErrNotFound.Error())
	})

	t.Run("Actor of Undo does not match the actor in Follow activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not the same as the actor of the original activity")
	})

	t.Run("Unsupported activity type for 'Undo'", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(unsupported.ID().URL())),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("Inbox Undo Follow", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, ibHandler.store.AddReference(store.Follower, service1IRI, service2IRI))

			it, err := ibHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))

			it, err = ibHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service2IRI))
		})

		t.Run("No IRI -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followNoIRI.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field of the 'Follow' activity")
		})

		t.Run("IRI not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followIRINotLocalService.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "this service is not the target for the 'Undo'")
		})

		t.Run("Not a follower", func(t *testing.T) {
			it, err := ibHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))
		})
	})

	t.Run("Outbox Undo Follow", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, obHandler.store.AddReference(store.Following, service2IRI, service1IRI))

			it, err := obHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			following, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(following, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))

			it, err = obHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			following, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(following, service1IRI))
		})

		t.Run("No IRI -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followNoIRI.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field")
		})

		t.Run("Actor not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followActorNotLocalService.ID().URL())),
				vocab.WithActor(service3IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "this service is not the actor for the 'Undo'")
		})

		t.Run("Not following", func(t *testing.T) {
			it, err := obHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))
		})
	})
}

func TestHandler_HandleUndoInviteWitnessActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	ibHandler, obHandler, ibSubscriber, obSubscriber, stop := startInboxOutboxWithMocks(t, service1IRI, service2IRI)
	defer stop()

	inviteWitness := vocab.NewInviteWitnessActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	inviteWitnessNoIRI := vocab.NewInviteWitnessActivity(
		vocab.NewObjectProperty(),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	inviteWitnessIRINotLocalService := vocab.NewInviteWitnessActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	inviteWitnessActorNotLocalService := vocab.NewInviteWitnessActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(newActivityID(service2IRI)),
		vocab.WithActor(service3IRI),
		vocab.WithTo(service1IRI),
	)

	require.NoError(t, obHandler.store.AddActivity(inviteWitness))
	require.NoError(t, obHandler.store.AddActivity(inviteWitnessNoIRI))
	require.NoError(t, obHandler.store.AddActivity(inviteWitnessActorNotLocalService))

	require.NoError(t, ibHandler.store.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, ibHandler.store.AddActivity(inviteWitness))
	require.NoError(t, ibHandler.store.AddActivity(inviteWitnessNoIRI))
	require.NoError(t, ibHandler.store.AddActivity(inviteWitnessIRINotLocalService))

	t.Run("Inbox Undo InviteWitness", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, ibHandler.store.AddReference(store.Witnessing, service1IRI, service2IRI))

			it, err := ibHandler.store.QueryReferences(store.Witnessing,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitness.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))

			it, err = ibHandler.store.QueryReferences(store.Witnessing,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service2IRI))
		})

		t.Run("No IRI -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitnessNoIRI.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field of the 'InviteWitness' activity")
		})

		t.Run("IRI not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitnessIRINotLocalService.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "this service is not the target for the 'Undo'")
		})

		t.Run("Not witnessing", func(t *testing.T) {
			it, err := ibHandler.store.QueryReferences(store.Witnessing,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitness.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))
		})
	})

	t.Run("Outbox Undo InviteWitness", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, obHandler.store.AddReference(store.Witness, service2IRI, service1IRI))

			it, err := obHandler.store.QueryReferences(store.Witness,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			following, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(following, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitness.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))

			it, err = obHandler.store.QueryReferences(store.Witness,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			following, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(following, service1IRI))
		})

		t.Run("No IRI -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitnessNoIRI.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field")
		})

		t.Run("Actor not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitnessActorNotLocalService.ID().URL())),
				vocab.WithActor(service3IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "this service is not the actor for the 'Undo'")
		})

		t.Run("Not a witness", func(t *testing.T) {
			it, err := obHandler.store.QueryReferences(store.Witness,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(inviteWitness.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))
		})
	})
}

func TestHandler_AnnounceAnchorCredential(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	t.Run("Anchor credential", func(t *testing.T) {
		targetProperty := vocab.NewObjectProperty(vocab.WithObject(
			vocab.NewObject(
				vocab.WithID(anchCredID),
				vocab.WithCID(cid),
				vocab.WithType(vocab.TypeContentAddressedStorage),
			),
		))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		if err != nil {
			panic(err)
		}

		published := time.Now()

		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			activityStore := memstore.New(cfg.ServiceName)
			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorCredential(create))

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchCredID)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Store error", func(t *testing.T) {
			errExpected := errors.New("injected query error")

			activityStore := &mocks.ActivityStore{}
			activityStore.QueryReferencesReturns(nil, errExpected)

			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			err := h.announceAnchorCredential(create)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
		})

		t.Run("Store iterator error", func(t *testing.T) {
			errExpected := errors.New("injected iterator error")

			activityStore := &mocks.ActivityStore{}
			it := &storemocks.ReferenceIterator{}
			it.NextReturns(nil, errExpected)

			activityStore.QueryReferencesReturns(it, nil)

			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			err := h.announceAnchorCredential(create)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
		})

		t.Run("No followers", func(t *testing.T) {
			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, memstore.New("service1"), ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorCredential(create))

			time.Sleep(50 * time.Millisecond)

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) == 0)
		})
	})

	t.Run("Anchor credential reference", func(t *testing.T) {
		refID := testutil.MustParseURL("https://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvaty")

		published := time.Now()

		create := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(
					vocab.NewAnchorCredentialReference(refID, anchCredID, cid),
				),
			),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			activityStore := memstore.New(cfg.ServiceName)
			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorCredentialRef(create))

			time.Sleep(50 * time.Millisecond)

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchCredID)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Store error", func(t *testing.T) {
			errExpected := errors.New("injected query error")

			activityStore := &mocks.ActivityStore{}
			activityStore.QueryReferencesReturns(nil, errExpected)

			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{}, spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.True(t, errors.Is(h.announceAnchorCredentialRef(create), errExpected))
		})

		t.Run("No followers", func(t *testing.T) {
			activityStore := memstore.New(cfg.ServiceName)
			ob := mocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, activityStore, ob, &apmocks.HTTPTransport{},
				spi.WithAnchorCredentialHandler(anchorCredHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorCredentialRef(create))

			time.Sleep(50 * time.Millisecond)

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) == 0)
		})
	})
}

type mockActivitySubscriber struct {
	mutex        sync.RWMutex
	activities   map[string]*vocab.ActivityType
	activityChan <-chan *vocab.ActivityType
}

func newMockActivitySubscriber(activityChan <-chan *vocab.ActivityType) *mockActivitySubscriber {
	return &mockActivitySubscriber{
		activities:   make(map[string]*vocab.ActivityType),
		activityChan: activityChan,
	}
}

func (l *mockActivitySubscriber) Listen() {
	for activity := range l.activityChan {
		l.mutex.Lock()
		l.activities[activity.ID().String()] = activity
		l.mutex.Unlock()
	}
}

func (l *mockActivitySubscriber) Activity(iri fmt.Stringer) *vocab.ActivityType {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.activities[iri.String()]
}

type stopFunc func()

func startInboxOutboxWithMocks(t *testing.T, inboxServiceIRI,
	outboxServiceIRI *url.URL) (*Inbox, *Outbox, *mockActivitySubscriber, *mockActivitySubscriber, stopFunc) {
	t.Helper()

	inboxCfg := &Config{
		ServiceName: "inbox1",
		ServiceIRI:  inboxServiceIRI,
	}

	outboxCfg := &Config{
		ServiceName: "outbox1",
		ServiceIRI:  outboxServiceIRI,
	}

	httpClient := &apmocks.HTTPTransport{}
	httpClient.GetReturns(nil, client.ErrNotFound)

	inboxHandler := NewInbox(inboxCfg, memstore.New(inboxCfg.ServiceName), mocks.NewOutbox(), httpClient)
	require.NotNil(t, inboxHandler)

	outboxHandler := NewOutbox(outboxCfg, memstore.New(outboxCfg.ServiceName), httpClient)
	require.NotNil(t, outboxHandler)

	inboxSubscriber := newMockActivitySubscriber(inboxHandler.Subscribe())
	outboxSubscriber := newMockActivitySubscriber(outboxHandler.Subscribe())

	go func() {
		go inboxSubscriber.Listen()
		go outboxSubscriber.Listen()

		inboxHandler.Start()
		inboxHandler.Start()
	}()

	return inboxHandler, outboxHandler, inboxSubscriber, outboxSubscriber,
		func() {
			inboxHandler.Stop()
			inboxHandler.Stop()
		}
}

func newActivityID(id fmt.Stringer) *url.URL {
	return testutil.NewMockID(id, uuid.New().String())
}

func newTransactionID(id fmt.Stringer) *url.URL {
	return testutil.NewMockID(id, uuid.New().String())
}

const anchorCredential1 = `{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
  ],
  "id": "https://sally.example.com/transactions/bafkreihwsn",
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
