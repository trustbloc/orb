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

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	storemocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

func TestNewInbox(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  testutil.MustParseURL("http://localhost:8301/services/service1"),
		BufferSize:  100,
	}

	h := NewInbox(cfg, &servicemocks.ActivityStore{}, &servicemocks.Outbox{}, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	require.Equal(t, lifecycle.StateNotStarted, h.State())

	h.Start()

	require.Equal(t, lifecycle.StateStarted, h.State())

	h.Stop()

	require.Equal(t, lifecycle.StateStopped, h.State())
}

func TestNewOutbox(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := NewOutbox(cfg, &servicemocks.ActivityStore{}, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	require.Equal(t, lifecycle.StateNotStarted, h.State())

	h.Start()

	require.Equal(t, lifecycle.StateStarted, h.State())

	h.Stop()

	require.Equal(t, lifecycle.StateStopped, h.State())
}

func TestNoOpProofHandler_HandleProof(t *testing.T) {
	require.Nil(t, (&noOpProofHandler{}).HandleProof(nil, "", time.Now(), nil))
}

func TestHandler_HandleUnsupportedActivity(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  testutil.MustParseURL("http://localhost:8301/services/service1"),
	}

	h := NewInbox(cfg, &servicemocks.ActivityStore{}, &servicemocks.Outbox{}, servicemocks.NewActorRetriever())
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

func TestHandler_InboxHandleCreateActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	anchorEventHandler := servicemocks.NewAnchorEventHandler()

	activityStore := memstore.New(cfg.ServiceName)
	ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

	require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
	require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

	h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(), spi.WithAnchorEventHandler(anchorEventHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("With anchor event", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			anchorEvent := aptestutil.NewMockAnchorEvent(t)

			anchorEventURL := anchorEvent.URL()[0]

			create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
				vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)))

			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, subscriber.Activity(create.ID()))

			_, exists := anchorEventHandler.AnchorEvent(anchorEventURL.String())
			require.True(t, exists)
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.AnchorEvent,
				store.NewCriteria(store.WithObjectIRI(anchorEventURL)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Handler error", func(t *testing.T) {
			anchorEvent := aptestutil.NewMockAnchorEvent(t)

			create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
				vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)))

			errExpected := fmt.Errorf("injected anchor cred handler error")

			anchorEventHandler.WithError(errExpected)
			defer func() { anchorEventHandler.WithError(nil) }()

			require.True(t, errors.Is(h.HandleActivity(create), errExpected))
		})
	})

	t.Run("With anchor event reference", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			anchorEvent := aptestutil.NewMockAnchorEventRef(t)

			anchorEventURL := anchorEvent.URL()[0]

			create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
				vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)))

			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, subscriber.Activity(create.ID()))

			_, exists := anchorEventHandler.AnchorEvent(anchorEventURL.String())
			require.True(t, exists)
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorEventURL)))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)

			it, err = activityStore.QueryReferences(store.AnchorEvent,
				store.NewCriteria(store.WithObjectIRI(anchorEventURL)))
			require.NoError(t, err)

			refs, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Handler error", func(t *testing.T) {
			errExpected := fmt.Errorf("injected anchor cred handler error")

			anchorEventHandler.WithError(errExpected)
			defer func() { anchorEventHandler.WithError(nil) }()

			create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
				vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEventRef(t))))

			require.True(t, errors.Is(h.HandleActivity(create), errExpected))
		})
	})

	t.Run("Unsupported object type", func(t *testing.T) {
		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeService)))))

		err := h.HandleActivity(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type in 'Create' activity")
	})
}

func TestHandler_OutboxHandleCreateActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	activityStore := memstore.New(cfg.ServiceName)

	h := NewOutbox(cfg, activityStore, servicemocks.NewActorRetriever())

	h.Start()
	defer h.Stop()

	t.Run("Embedded anchor event", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEvent(t)

		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
			),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			it, err := activityStore.QueryReferences(store.AnchorEvent,
				store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})
	})

	t.Run("Anchor event reference", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEvent(t)

		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
			),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			it, err := activityStore.QueryReferences(store.AnchorEvent,
				store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})
	})

	t.Run("Unsupported object type", func(t *testing.T) {
		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeService)))))

		err := h.HandleActivity(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type in 'Create' activity")
	})

	t.Run("Anchor credential storage error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected storage error")

		s := &servicemocks.ActivityStore{}
		s.AddReferenceReturns(errExpected)

		obHandler := NewOutbox(cfg, s, servicemocks.NewActorRetriever())

		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					aptestutil.NewMockAnchorEvent(t),
				),
			),
		)

		err := obHandler.HandleActivity(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
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

	ob := servicemocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	apClient := servicemocks.NewActorRetriever().
		WithActor(vocab.NewService(service2IRI)).
		WithActor(vocab.NewService(service3IRI))

	followerAuth := servicemocks.NewActorAuth()

	h := NewInbox(cfg, as, ob, apClient, spi.WithFollowAuth(followerAuth))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept", func(t *testing.T) {
		followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
			vocab.WithID(aptestutil.NewActivityID(service3IRI)),
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
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no actor specified")
	})

	t.Run("No object IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no IRI specified")
	})

	t.Run("Object IRI does not match target service IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "this service is not the target object for the 'Follow'")
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		apClient.WithError(client.ErrNotFound)
		defer func() { apClient.WithError(nil) }()

		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service4IRI)),
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
			vocab.WithID(aptestutil.NewActivityID(service3IRI)),
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

	ob := servicemocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	apClient := servicemocks.NewActorRetriever().
		WithActor(vocab.NewService(service2IRI)).
		WithActor(vocab.NewService(service3IRI))

	witnessInvitationAuth := servicemocks.NewActorAuth()

	h := NewInbox(cfg, as, ob, apClient, spi.WithInviteWitnessAuth(witnessInvitationAuth))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept", func(t *testing.T) {
		witnessInvitationAuth.WithAccept()

		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		require.NoError(t, h.HandleActivity(invite))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(invite.ID()))

		it, err := h.store.QueryReferences(store.Witnessing, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		witnesses, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(witnesses, service2IRI))
		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 1)

		// Post another invitation. Should reply with accept since it's already a invite.
		invite = vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		require.NoError(t, h.HandleActivity(invite))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(invite.ID()))

		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 2)
	})

	t.Run("Reject", func(t *testing.T) {
		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		witnessInvitationAuth.WithReject()

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(invite))

			time.Sleep(50 * time.Millisecond)

			require.Nil(t, subscriber.Activity(invite.ID()))

			it, err := h.store.QueryReferences(store.Witnessing, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
			require.NoError(t, err)

			witnesses, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.False(t, containsIRI(witnesses, service3IRI))
			require.Len(t, ob.Activities().QueryByType(vocab.TypeReject), 1)
		})
	})

	t.Run("No actor in Witness activity", func(t *testing.T) {
		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		err := h.HandleActivity(invite)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no actor specified")
	})

	t.Run("No object IRI in Invite witness activity", func(t *testing.T) {
		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		err := h.HandleActivity(invite)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no object specified in 'Invite' activity")
	})

	t.Run("Object IRI does not match target service IRI in Witness activity", func(t *testing.T) {
		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service3IRI))),
		)

		err := h.HandleActivity(invite)
		require.Error(t, err)
		require.Contains(t, err.Error(), "this service is not the target object for the 'Invite'")
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		apClient.WithError(client.ErrNotFound)
		defer func() { apClient.WithError(nil) }()

		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service4IRI)),
			vocab.WithActor(service4IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		require.True(t, errors.Is(h.HandleActivity(invite), client.ErrNotFound))
	})

	t.Run("AuthorizeWitness error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected authorize error")

		witnessInvitationAuth.WithError(errExpected)

		defer func() {
			witnessInvitationAuth.WithError(nil)
		}()

		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		err := h.HandleActivity(invite)
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

	ob := servicemocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := NewInbox(cfg, as, ob, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Accept Follow -> Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		// Make sure the activity is in our outbox or else it will fail check.
		require.NoError(t, as.AddActivity(follow))
		require.NoError(t, as.AddReference(store.Outbox, h.ServiceIRI, follow.ID().URL()))

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
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
		require.Contains(t, err.Error(), "already in the 'FOLLOWING' collection")
	})

	t.Run("Accept Witness -> Success", func(t *testing.T) {
		invite := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		// Make sure the activity is in our outbox or else it will fail check.
		require.NoError(t, as.AddActivity(invite))
		require.NoError(t, as.AddReference(store.Outbox, h.ServiceIRI, invite.ID().URL()))

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(invite)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
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
		require.Contains(t, err.Error(), "already in the 'WITNESS' collection")
	})

	t.Run("No actor in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept), "no actor specified in 'Accept' activity")
	})

	t.Run("No activity specified in 'object' field", func(t *testing.T) {
		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no activity specified in the 'object' field of the 'Accept' activity")
	})

	t.Run("Unsupported activity type", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"unsupported activity type [Announce] in the 'object' field of the 'Accept' activity")
	})

	t.Run("No actor specified in the activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no actor specified in the object of the 'Accept' activity")
	})

	t.Run("Actor in object does not match target service IRI in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"the actor in the object of the 'Accept' activity is not this service")
	})
}

func TestHandler_HandleAcceptActivityValidationError(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := servicemocks.NewOutbox()
	as := &servicemocks.ActivityStore{}

	h := NewInbox(cfg, as, ob, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	follow := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	accept := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(follow)),
		vocab.WithID(aptestutil.NewActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
	)

	t.Run("Query error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		as.QueryActivitiesReturns(nil, errExpected)

		err := h.HandleActivity(accept)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Not found", func(t *testing.T) {
		it := memstore.NewActivityIterator(nil, -1)

		as.QueryActivitiesReturns(it, nil)

		require.True(t, errors.Is(h.HandleActivity(accept), store.ErrNotFound))
	})

	t.Run("Actor mismatch", func(t *testing.T) {
		f := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(follow.ID().URL()),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		it := memstore.NewActivityIterator([]*vocab.ActivityType{f}, -1)

		as.QueryActivitiesReturns(it, nil)

		err := h.HandleActivity(accept)
		require.Error(t, err)
		require.Contains(t, err.Error(), "actors do not match")
	})

	t.Run("Type mismatch", func(t *testing.T) {
		f := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(follow.ID().URL()),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		it := memstore.NewActivityIterator([]*vocab.ActivityType{f}, -1)

		as.QueryActivitiesReturns(it, nil)

		err := h.HandleActivity(accept)
		require.Error(t, err)
		require.Contains(t, err.Error(), "types do not match")
	})
}

func TestHandler_HandleAcceptActivityError(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := servicemocks.NewOutbox()
	as := &servicemocks.ActivityStore{}

	h := NewInbox(cfg, as, ob, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	follow := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	acceptFollow := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(follow)),
		vocab.WithID(aptestutil.NewActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
	)

	invite := vocab.NewInviteActivity(
		vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
	)

	acceptInvite := vocab.NewAcceptActivity(
		vocab.NewObjectProperty(vocab.WithActivity(invite)),
		vocab.WithID(aptestutil.NewActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
	)

	t.Run("Accept Follow query error", func(t *testing.T) {
		as.QueryActivitiesReturns(memstore.NewActivityIterator([]*vocab.ActivityType{follow}, 1), nil)

		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(nil, errExpected)

		err := h.HandleActivity(acceptFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept Follow AddReference error", func(t *testing.T) {
		as.QueryActivitiesReturns(memstore.NewActivityIterator([]*vocab.ActivityType{follow}, 1), nil)

		errExpected := fmt.Errorf("injected storage error")

		it := &storemocks.ReferenceIterator{}
		it.NextReturns(nil, store.ErrNotFound)
		as.QueryReferencesReturns(it, nil)
		as.AddReferenceReturns(errExpected)

		err := h.HandleActivity(acceptFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept Invite query error", func(t *testing.T) {
		as.QueryActivitiesReturns(memstore.NewActivityIterator([]*vocab.ActivityType{invite}, 1), nil)

		errExpected := fmt.Errorf("injected storage error")

		as.QueryReferencesReturns(nil, errExpected)

		err := h.HandleActivity(acceptInvite)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Accept Invite AddReference error", func(t *testing.T) {
		as.QueryActivitiesReturns(memstore.NewActivityIterator([]*vocab.ActivityType{invite}, 1), nil)

		errExpected := fmt.Errorf("injected storage error")

		it := &storemocks.ReferenceIterator{}
		it.NextReturns(nil, store.ErrNotFound)
		as.QueryReferencesReturns(it, nil)
		as.AddReferenceReturns(errExpected)

		err := h.HandleActivity(acceptInvite)
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

	ob := servicemocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := NewInbox(cfg, as, ob, servicemocks.NewActorRetriever())
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Reject Follow -> Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
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
		follow := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
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
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject), "no actor specified in 'Reject' activity")
	})

	t.Run("No Follow activity specified in 'object' field", func(t *testing.T) {
		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no activity specified in the 'object' field of the 'Reject' activity")
	})

	t.Run("Unsupported activity type", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"unsupported activity type [Announce] in the 'object' field of the 'Accept' activity")
	})

	t.Run("No actor specified in the activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no actor specified in the object of the 'Reject' activity")
	})

	t.Run("Actor does not match target service IRI in Reject activity", func(t *testing.T) {
		follow := vocab.NewInviteActivity(
			vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
		)

		reject := vocab.NewRejectActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
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

	targetID := testutil.MustParseURL(
		"http://localhost:8301/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")
	target2ID := testutil.MustParseURL(
		"http://localhost:8301/cas/bafkrwkhwinurpgfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	anchorEventHandler := servicemocks.NewAnchorEventHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), &servicemocks.Outbox{}, servicemocks.NewActorRetriever(),
		spi.WithAnchorEventHandler(anchorEventHandler))
	require.NotNil(t, h)

	require.NoError(t, h.store.AddReference(store.AnchorEvent, target2ID, h.ServiceIRI))

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Anchor credential ref - collection (no embedded object)", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEventRef(t)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
			),
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
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))

		it, err := h.store.QueryReferences(store.AnchorEvent,
			store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)

		it, err = h.store.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err = storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
	})

	t.Run("Anchor credential ref - ordered collection (no embedded object)", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEventRef(t)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithOrderedCollection(
					vocab.NewOrderedCollection(items),
				),
			),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))

		it, err := h.store.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
	})

	t.Run("Anchor credential ref (with embedded object)", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEvent(t)

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
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(announce.ID()))

		it, err := h.store.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
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
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting 'Info' type")
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
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting 'Info' type")
	})

	t.Run("Anchor credential ref - unsupported object type", func(t *testing.T) {
		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		err := h.HandleActivity(announce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported object type for 'Announce'")
	})

	t.Run("Add to shares error", func(t *testing.T) {
		published := time.Now()

		announce := vocab.NewAnnounceActivity(
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection([]*vocab.ObjectProperty{
						vocab.NewObjectProperty(
							vocab.WithAnchorEvent(aptestutil.NewMockAnchorEventRef(t)),
						),
					}),
				),
			),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		errExpected := errors.New("injected AddReference error")

		apStore := &servicemocks.ActivityStore{}
		apStore.QueryReferencesReturns(memstore.NewReferenceIterator(nil, 0), nil)
		apStore.AddReferenceReturnsOnCall(1, errExpected)

		ib := NewInbox(cfg, apStore, &servicemocks.Outbox{}, servicemocks.NewActorRetriever(),
			spi.WithAnchorEventHandler(anchorEventHandler))
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		require.NoError(t, ib.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		it, err := ib.store.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(targetID)))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.Empty(t, refs)
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

	ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))
	witness := servicemocks.NewWitnessHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), ob, servicemocks.NewActorRetriever(), spi.WithWitness(witness))
	require.NotNil(t, h)

	require.NoError(t, h.store.AddReference(store.Witnessing, h.ServiceIRI, service1IRI))

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	t.Run("Success", func(t *testing.T) {
		witness.WithProof([]byte(proof))

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		require.NoError(t, h.HandleActivity(offer))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(offer.ID()))
		require.Len(t, witness.AnchorCreds(), 1)
	})

	t.Run("No response from witness -> error", func(t *testing.T) {
		witness.WithProof(nil)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to unmarshal proof")
	})

	t.Run("Witness error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected witness error")

		witness.WithError(errExpected)
		defer witness.WithError(nil)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		require.True(t, errors.Is(h.HandleActivity(offer), errExpected))
	})

	t.Run("No start time", func(t *testing.T) {
		endTime := time.Now().Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "startTime is required")
	})

	t.Run("No end time", func(t *testing.T) {
		startTime := time.Now()

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "endTime is required")
	})

	t.Run("Invalid object type", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeAnnounce)))),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor event is required")
	})

	t.Run("No object", func(t *testing.T) {
		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor event is required")
	})

	t.Run("Not witnessing actor", func(t *testing.T) {
		witness.WithProof([]byte(proof))

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithID(aptestutil.NewActivityID(service3IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
		)

		err := h.HandleActivity(offer)
		require.NoError(t, err)
	})

	t.Run("Invalid target", func(t *testing.T) {
		witness.WithProof([]byte(proof))

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		offer := vocab.NewOfferActivity(
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
			vocab.WithID(aptestutil.NewActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object target IRI must be set to https://w3id.org/activityanchors#AnchorWitness")
	})
}

func TestHandler_HandleAcceptOfferActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.WARNING)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	proofHandler := servicemocks.NewProofHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), &servicemocks.Outbox{}, servicemocks.NewActorRetriever(),
		spi.WithProofHandler(proofHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	anchorEvent := aptestutil.NewMockAnchorEvent(t)

	anchorEventURL := anchorEvent.URL()[0]

	startTime := time.Now()
	endTime := startTime.Add(time.Hour)

	offer := vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithAnchorEvent(anchorEvent)),
		vocab.WithID(aptestutil.NewActivityID(service1IRI)),
		vocab.WithActor(service1IRI),
		vocab.WithTo(service2IRI),
		vocab.WithStartTime(&startTime),
		vocab.WithEndTime(&endTime),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
	)

	// Make sure the activity is in our outbox or else it will fail check.
	require.NoError(t, h.store.AddActivity(offer))
	require.NoError(t, h.store.AddReference(store.Outbox, h.ServiceIRI, offer.ID().URL()))

	result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
	require.NoError(t, err)

	objProp := vocab.NewObjectProperty(vocab.WithActivity(vocab.NewOfferActivity(
		vocab.NewObjectProperty(vocab.WithIRI(anchorEvent.Index())),
		vocab.WithID(offer.ID().URL()),
		vocab.WithActor(offer.Actor()),
		vocab.WithTo(offer.To()...),
		vocab.WithTarget(offer.Target()),
	)))

	acceptOffer := vocab.NewAcceptActivity(objProp,
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithTo(offer.Actor(), vocab.PublicIRI),
		vocab.WithActor(service1IRI),
		vocab.WithResult(vocab.NewObjectProperty(
			vocab.WithObject(vocab.NewObject(
				vocab.WithType(vocab.TypeAnchorReceipt),
				vocab.WithInReplyTo(anchorEvent.Index()),
				vocab.WithStartTime(&startTime),
				vocab.WithEndTime(&endTime),
				vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result))),
			),
			)),
		))

	bytes, err := canonicalizer.MarshalCanonical(acceptOffer)
	require.NoError(t, err)
	t.Log(string(bytes))

	t.Run("Success", func(t *testing.T) {
		require.NoError(t, h.HandleActivity(acceptOffer))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(acceptOffer.ID()))

		require.NotEmpty(t, proofHandler.Proof(anchorEvent.Index().String()))
	})

	t.Run("HandleProof error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected witness error")

		proofHandler.WithError(errExpected)
		defer proofHandler.WithError(nil)

		require.True(t, errors.Is(h.HandleActivity(acceptOffer), errExpected))
	})

	t.Run("inReplyTo does not match object IRI in offer activity", func(t *testing.T) {
		a := vocab.NewAcceptActivity(objProp,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(aptestutil.NewActivityID(service1IRI)),
					vocab.WithStartTime(&startTime),
					vocab.WithEndTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		e := h.handleAcceptActivity(a)
		require.Error(t, e)
		require.Contains(t, e.Error(),
			"the anchors URL of the anchor event in the original 'Offer' does not match the IRI in the 'inReplyTo' field")
	})

	t.Run("No object", func(t *testing.T) {
		a := vocab.NewAcceptActivity(nil,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithEndTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		err = h.validateAcceptOfferActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object is required")
	})

	t.Run("No object IRI", func(t *testing.T) {
		a := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(vocab.NewOfferActivity(
				vocab.NewObjectProperty(),
				vocab.WithID(offer.ID().URL()),
				vocab.WithActor(offer.Actor()),
				vocab.WithTo(offer.To()...),
			))),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithEndTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object IRI is required")
	})

	t.Run("No result", func(t *testing.T) {
		a := vocab.NewAcceptActivity(objProp,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "result is required")
	})

	t.Run("No start time", func(t *testing.T) {
		a := vocab.NewAcceptActivity(objProp,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithEndTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "startTime is required")
	})

	t.Run("No end time", func(t *testing.T) {
		a := vocab.NewAcceptActivity(objProp,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "endTime is required")
	})

	t.Run("Invalid object type", func(t *testing.T) {
		a := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(vocab.NewFollowActivity(
				vocab.NewObjectProperty(vocab.WithIRI(anchorEventURL)),
				vocab.WithID(offer.ID().URL()),
				vocab.WithActor(offer.Actor()),
				vocab.WithTo(offer.To()...),
				vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI))),
			))),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				),
			)),
		)

		err = h.validateAcceptOfferActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object is not of type 'Offer'")
	})

	t.Run("No attachment", func(t *testing.T) {
		a := vocab.NewAcceptActivity(
			objProp,
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithEndTime(&endTime),
				)),
			)),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting exactly one attachment")
	})

	t.Run("Invalid target", func(t *testing.T) {
		a := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(vocab.WithActivity(vocab.NewOfferActivity(
				vocab.NewObjectProperty(vocab.WithIRI(anchorEventURL)),
				vocab.WithID(offer.ID().URL()),
				vocab.WithActor(offer.Actor()),
				vocab.WithTo(offer.To()...),
			))),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(offer.Actor(), vocab.PublicIRI),
			vocab.WithActor(service1IRI),
			vocab.WithResult(vocab.NewObjectProperty(
				vocab.WithObject(vocab.NewObject(
					vocab.WithType(vocab.TypeAnchorReceipt),
					vocab.WithInReplyTo(anchorEventURL),
					vocab.WithStartTime(&endTime),
					vocab.WithEndTime(&endTime),
					vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithObject(result)))),
				)),
			),
		)

		err = h.handleAcceptActivity(a)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object target IRI must be set to https://w3id.org/activityanchors#AnchorWitness")
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
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followNotStored := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followNoIRI := vocab.NewFollowActivity(
		vocab.NewObjectProperty(),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followIRINotLocalService := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	followActorNotLocalService := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service3IRI),
		vocab.WithTo(service1IRI),
	)

	followNoActor := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithTo(service1IRI),
	)

	unsupported := vocab.NewRejectActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
		vocab.WithID(aptestutil.NewActivityID(ibHandler.ServiceIRI)),
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
	require.NoError(t, ibHandler.store.AddActivity(followNoActor))
	require.NoError(t, ibHandler.store.AddActivity(unsupported))

	t.Run("No actor in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, ibHandler.HandleActivity(undo), "no actor specified in 'Undo' activity")
	})

	t.Run("No object in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, ibHandler.HandleActivity(undo),
			"no activity specified in 'object' field of the 'Undo' activity")
	})

	t.Run("Activity not found in storage", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(followNotStored)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.True(t, errors.Is(err, store.ErrNotFound))
	})

	t.Run("No actor in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(followNoActor)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.EqualError(t, err, "no actor specified in 'Follow' activity")
	})

	t.Run("Actor of Undo does not match the actor in Follow activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not the same as the actor of the original activity")
	})

	t.Run("Unsupported activity type for 'Undo'", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(unsupported)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := ibHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("Transient error", func(t *testing.T) {
		inboxCfg := &Config{
			ServiceName: "inbox1",
			ServiceIRI:  service1IRI,
		}

		errExpected := errors.New("injected storage error")

		s := &servicemocks.ActivityStore{}
		s.GetActivityReturns(nil, errExpected)

		ob := servicemocks.NewOutbox().WithError(errExpected)

		inboxHandler := NewInbox(inboxCfg, s, ob, servicemocks.NewActorRetriever())
		require.NotNil(t, inboxHandler)

		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithID(aptestutil.NewActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := inboxHandler.HandleActivity(undo)
		require.True(t, orberrors.IsTransient(err))

		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
		)

		err = inboxHandler.announceAnchorEvent(create)
		require.True(t, orberrors.IsTransient(err))

		err = inboxHandler.announceAnchorEventRef(create)
		require.True(t, orberrors.IsTransient(err))
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
				vocab.NewObjectProperty(vocab.WithActivity(follow)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
				vocab.NewObjectProperty(vocab.WithActivity(followNoIRI)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in the 'Follow' activity")
		})

		t.Run("IRI not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(followIRINotLocalService)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
				vocab.NewObjectProperty(vocab.WithActivity(follow)),
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
				vocab.NewObjectProperty(vocab.WithActivity(follow)),
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
				vocab.NewObjectProperty(vocab.WithActivity(followNoIRI)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field")
		})

		t.Run("Actor not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(followActorNotLocalService)),
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
				vocab.NewObjectProperty(vocab.WithActivity(follow)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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

	invite := vocab.NewInviteActivity(
		vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
	)

	inviteWitnessNoTarget := vocab.NewInviteActivity(
		vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
		vocab.WithID(aptestutil.NewActivityID(vocab.AnchorWitnessTargetIRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	inviteWitnessIRINotLocalService := vocab.NewInviteActivity(
		vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service3IRI))),
	)

	inviteWitnessActorNotLocalService := vocab.NewInviteActivity(
		vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service3IRI),
		vocab.WithTo(service1IRI),
		vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(service1IRI))),
	)

	require.NoError(t, obHandler.store.AddActivity(invite))
	require.NoError(t, obHandler.store.AddActivity(inviteWitnessNoTarget))
	require.NoError(t, obHandler.store.AddActivity(inviteWitnessActorNotLocalService))

	require.NoError(t, ibHandler.store.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, ibHandler.store.AddActivity(invite))
	require.NoError(t, ibHandler.store.AddActivity(inviteWitnessNoTarget))
	require.NoError(t, ibHandler.store.AddActivity(inviteWitnessIRINotLocalService))

	t.Run("Inbox Undo Invite", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, ibHandler.store.AddReference(store.Witnessing, service1IRI, service2IRI))

			it, err := ibHandler.store.QueryReferences(store.Witnessing,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(invite)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
				vocab.NewObjectProperty(vocab.WithActivity(inviteWitnessNoTarget)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in the 'Invite' activity")
		})

		t.Run("IRI not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(inviteWitnessIRINotLocalService)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
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
				vocab.NewObjectProperty(vocab.WithActivity(invite)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))
		})
	})

	t.Run("Outbox Undo Invite", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, obHandler.store.AddReference(store.Witness, service2IRI, service1IRI))

			it, err := obHandler.store.QueryReferences(store.Witness,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			winesses, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(winesses, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(invite)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))

			it, err = obHandler.store.QueryReferences(store.Witness,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			winesses, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(winesses, service1IRI))
		})

		t.Run("No IRI -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(inviteWitnessNoTarget)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := obHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no IRI specified in 'object' field")
		})

		t.Run("Actor not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(inviteWitnessActorNotLocalService)),
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
				vocab.NewObjectProperty(vocab.WithActivity(invite)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))
		})
	})
}

func TestHandler_HandleUndoLikeActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	ref := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-CeE1odHRwczovL3NhbGx5LmV4YW1wbGUuY29tL2Nhcy91RWlDc0ZwLWZ0OHRJMURGR2JYczc4dHctSFM1NjFtTVBhM1o2R3NHQUhFbHJOUXhCaXBmczovL2JhZmtyZWlmbWMycHo3bjZsamRrZGNydG5wbTU3ZnhiNmR1eGh2dnRkYjV2eG02cTJ5Z2FieXNsbGd1") //nolint:lll
	additionalRef1 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhodHRwczovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw")                                                                                                            //nolint:lll
	additionalRef2 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhoxHRwxzovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw")                                                                                                            //nolint:lll

	publishedTime := time.Now()

	ibHandler, obHandler, ibSubscriber, obSubscriber, stop := startInboxOutboxWithMocks(t, service1IRI, service2IRI)
	defer stop()

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(
				vocab.NewAnchorEvent(vocab.WithURL(ref))),
		),
		vocab.WithID(aptestutil.NewActivityID(service2IRI)),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&publishedTime),
		vocab.WithResult(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2))),
			),
		),
	)

	require.NoError(t, obHandler.store.AddActivity(like))

	require.NoError(t, ibHandler.store.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, ibHandler.store.AddActivity(like))

	t.Run("Inbox Undo Like", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, ibHandler.store.AddReference(store.Like, ref, like.ID().URL()))

			it, err := ibHandler.store.QueryReferences(store.Like,
				store.NewCriteria(store.WithObjectIRI(ref)))
			require.NoError(t, err)

			likes, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(likes, like.ID().URL()))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(like)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, ibHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, ibSubscriber.Activity(undo.ID()))

			it, err = ibHandler.store.QueryReferences(store.Like,
				store.NewCriteria(store.WithObjectIRI(ibHandler.ServiceIRI)))
			require.NoError(t, err)

			likes, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(likes, like.ID().URL()))
		})

		t.Run("No URL in anchor reference", func(t *testing.T) {
			likeNoURL := vocab.NewLikeActivity(
				vocab.NewObjectProperty(
					vocab.WithAnchorEvent(
						vocab.NewAnchorEvent()),
				),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI, vocab.PublicIRI),
				vocab.WithPublishedTime(&publishedTime),
				vocab.WithResult(
					vocab.NewObjectProperty(
						vocab.WithAnchorEvent(
							vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2))),
					),
				),
			)

			require.NoError(t, ibHandler.store.AddActivity(likeNoURL))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(likeNoURL)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			err := ibHandler.HandleActivity(undo)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid anchor reference in the 'Like' activity")
		})
	})

	t.Run("Outbox Undo Like", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, obHandler.store.AddReference(store.Liked, obHandler.ServiceIRI, like.ID().URL()))

			it, err := obHandler.store.QueryReferences(store.Liked,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			liked, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(liked, like.ID().URL()))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithActivity(like)),
				vocab.WithID(aptestutil.NewActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, obHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			require.NotNil(t, obSubscriber.Activity(undo.ID()))

			it, err = obHandler.store.QueryReferences(store.Liked,
				store.NewCriteria(store.WithObjectIRI(obHandler.ServiceIRI)))
			require.NoError(t, err)

			liked, err = storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(liked, like.ID().URL()))
		})
	})
}

func TestHandler_AnnounceAnchorEvent(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	anchorEventHandler := servicemocks.NewAnchorEventHandler()

	t.Run("Anchor credential", func(t *testing.T) {
		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(vocab.WithAnchorEvent(aptestutil.NewMockAnchorEvent(t))),
		)

		t.Run("Success", func(t *testing.T) {
			activityStore := memstore.New(cfg.ServiceName)
			ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

			h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(),
				spi.WithAnchorEventHandler(anchorEventHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorEvent(create))

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)
		})

		t.Run("Add to 'shares' error -> ignore", func(t *testing.T) {
			errExpected := errors.New("injected store error")

			activityStore := &servicemocks.ActivityStore{}
			activityStore.AddReferenceReturns(errExpected)

			ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(),
				spi.WithAnchorEventHandler(anchorEventHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorEvent(create))
		})
	})

	t.Run("Anchor event reference", func(t *testing.T) {
		anchorEvent := aptestutil.NewMockAnchorEventRef(t)

		create := aptestutil.NewMockCreateActivity(service1IRI, service2IRI,
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					anchorEvent,
				),
			),
		)

		t.Run("Success", func(t *testing.T) {
			activityStore := memstore.New(cfg.ServiceName)
			ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service3IRI))
			require.NoError(t, activityStore.AddReference(store.Follower, service2IRI, service1IRI))

			h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(),
				spi.WithAnchorEventHandler(anchorEventHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorEventRef(create))

			time.Sleep(50 * time.Millisecond)

			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
			require.NoError(t, err)

			refs, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)
			require.NotEmpty(t, refs)
		})

		t.Run("Add to 'shares' error -> ignore", func(t *testing.T) {
			errExpected := errors.New("injected store error")

			activityStore := &servicemocks.ActivityStore{}
			activityStore.AddReferenceReturns(errExpected)

			ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

			h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(),
				spi.WithAnchorEventHandler(anchorEventHandler))
			require.NotNil(t, h)

			h.Start()
			defer h.Stop()

			require.NoError(t, h.announceAnchorEventRef(create))
		})
	})
}

func TestHandler_InboxHandleLikeActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	actor := testutil.MustParseURL("https://witness1.example.com/services/orb")
	additionalRef1 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhodHRwczovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw") //nolint:lll
	additionalRef2 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhoxHRwxzovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw") //nolint:lll

	anchorEvent := aptestutil.NewMockAnchorEventRef(t)

	publishedTime := time.Now()

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	anchorEventHandler := servicemocks.NewAnchorEventHandler()

	activityStore := memstore.New(cfg.ServiceName)
	ob := servicemocks.NewOutbox().WithActivityID(testutil.NewMockID(service2IRI, "/activities/123456789"))

	h := NewInbox(cfg, activityStore, ob, servicemocks.NewActorRetriever(), spi.WithAnchorEventHandler(anchorEventHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	subscriber := newMockActivitySubscriber(h.Subscribe())
	go subscriber.Listen()

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(anchorEvent),
		),
		vocab.WithID(testutil.NewMockID(service2IRI, "/activities")),
		vocab.WithActor(actor),
		vocab.WithTo(service1IRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&publishedTime),
		vocab.WithResult(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2)))),
		),
	)

	t.Run("Success", func(t *testing.T) {
		require.NoError(t, h.HandleActivity(like))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(like.ID()))

		it, err := activityStore.QueryReferences(store.Like,
			store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
	})

	t.Run("No result -> Success", func(t *testing.T) {
		likeNoResult := vocab.NewLikeActivity(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(anchorEvent),
			),
			vocab.WithID(testutil.NewMockID(service2IRI, "/activities")),
			vocab.WithActor(actor),
			vocab.WithTo(service1IRI, vocab.PublicIRI),
			vocab.WithPublishedTime(&publishedTime),
		)

		require.NoError(t, h.HandleActivity(likeNoResult))

		time.Sleep(50 * time.Millisecond)

		require.NotNil(t, subscriber.Activity(likeNoResult.ID()))

		it, err := activityStore.QueryReferences(store.Like,
			store.NewCriteria(store.WithObjectIRI(anchorEvent.URL()[0])))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
	})

	t.Run("Invalid like", func(t *testing.T) {
		invalidLike := vocab.NewLikeActivity(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					vocab.NewAnchorEvent())),
			vocab.WithID(testutil.NewMockID(service2IRI, "/activities")),
			vocab.WithActor(actor),
			vocab.WithTo(service1IRI, vocab.PublicIRI),
			vocab.WithPublishedTime(&publishedTime),
			vocab.WithResult(
				vocab.NewObjectProperty(
					vocab.WithAnchorEvent(
						vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2)))),
			),
		)

		err := h.HandleActivity(invalidLike)
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor reference URL is required")
	})

	t.Run("Handler error", func(t *testing.T) {
		errExpected := errors.New("injected handler error")

		h := NewInbox(cfg, activityStore, ob,
			servicemocks.NewActorRetriever(),
			spi.WithAnchorEventHandler(servicemocks.NewAnchorEventHandler()),
			spi.WithAnchorEventAcknowledgementHandler(
				servicemocks.NewAnchorEventAcknowledgementHandler().
					WithError(errExpected),
			),
		)
		require.NotNil(t, h)

		h.Start()
		defer h.Stop()

		err := h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &servicemocks.ActivityStore{}
		activityStore.AddReferenceReturns(errExpected)

		h := NewInbox(cfg, activityStore, ob,
			servicemocks.NewActorRetriever(),
			spi.WithAnchorEventHandler(anchorEventHandler),
		)
		require.NotNil(t, h)

		h.Start()
		defer h.Stop()

		err := h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestHandler_OutboxHandleLikeActivity(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	actor := testutil.MustParseURL("https://witness1.example.com/services/orb")
	additionalRef1 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhodHRwczovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw") //nolint:lll
	additionalRef2 := testutil.MustParseURL("hl:uEiCsFp-ft8tI1DFGbXs78tw-HS561mMPa3Z6GsGAHElrNQ:uoQ-BeDhoxHRwxzovL2V4YW1wbGUuY29tL2NmMTQ5YTY4LTA4NTYtNDMwNC1hOWVjLTM0NzU2NzU1NDE2Yw") //nolint:lll

	publishedTime := time.Now()

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	activityStore := memstore.New(cfg.ServiceName)

	h := NewOutbox(cfg, activityStore, servicemocks.NewActorRetriever())

	h.Start()
	defer h.Stop()

	like := vocab.NewLikeActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(
				aptestutil.NewMockAnchorEventRef(t),
			),
		),
		vocab.WithID(testutil.NewMockID(service2IRI, "/activities")),
		vocab.WithActor(actor),
		vocab.WithTo(service1IRI, vocab.PublicIRI),
		vocab.WithPublishedTime(&publishedTime),
		vocab.WithResult(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2)))),
		),
	)

	t.Run("Success", func(t *testing.T) {
		require.NoError(t, h.HandleActivity(like))

		it, err := activityStore.QueryReferences(store.Liked,
			store.NewCriteria(store.WithObjectIRI(service2IRI)))
		require.NoError(t, err)

		refs, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
		require.Equal(t, like.ID().String(), refs[0].String())
	})

	t.Run("No anchor ref", func(t *testing.T) {
		invalidLike := vocab.NewLikeActivity(
			vocab.NewObjectProperty(
				vocab.WithAnchorEvent(
					vocab.NewAnchorEvent())),
			vocab.WithID(testutil.NewMockID(service2IRI, "/activities")),
			vocab.WithActor(actor),
			vocab.WithTo(service1IRI, vocab.PublicIRI),
			vocab.WithPublishedTime(&publishedTime),
			vocab.WithResult(
				vocab.NewObjectProperty(
					vocab.WithAnchorEvent(
						vocab.NewAnchorEvent(vocab.WithURL(additionalRef1, additionalRef2)))),
			),
		)

		require.EqualError(t, h.HandleActivity(invalidLike), "no anchor reference URL in 'Like' activity")
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &servicemocks.ActivityStore{}
		activityStore.AddReferenceReturns(errExpected)

		h := NewOutbox(cfg, activityStore, servicemocks.NewActorRetriever())

		h.Start()
		defer h.Stop()

		err := h.HandleActivity(like)
		require.Error(t, err)
		require.Contains(t, err.Error(), err.Error())
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

	apClient := servicemocks.NewActorRetriever()

	inboxHandler := NewInbox(inboxCfg, memstore.New(inboxCfg.ServiceName), servicemocks.NewOutbox(), apClient)
	require.NotNil(t, inboxHandler)

	outboxHandler := NewOutbox(outboxCfg, memstore.New(outboxCfg.ServiceName), apClient)
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

func TestNoOpAnchorEventAcknowledgementHandler(t *testing.T) {
	actor := testutil.MustParseURL("https://orb.domain2.com/services/orb")
	ref := testutil.MustParseURL("hl:uEiC0IYovFG8fmxcyK-9049AY2VUbQmb6K6x9XmbCSf4_Mg:" +
		"uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQzBJWW92Rkc4Zm14Y3lLLTkwNDlBWTJWVWJRbWI2SzZ4OVhtYkNTZjRfTWc")
	additionalRefs := []*url.URL{
		testutil.MustParseURL("hl:uEiC0IYovFG8fmxcyK-9049AY2VUbQmb6K6x9XmbCSf4_Mg:" +
			"uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzBJWW92Rkc4Zm14Y3lLLTkwND" +
			"lBWTJWVWJRbWI2SzZ4OVhtYkNTZjRfTWd4QmlwZnM6Ly9iYWZrcmVpZnVlZ2ZjNmZkcGQ2bnJvbX" +
			"JsNTUyb2h1YXkzZmtyd3F0ZzdpdjJ5N2s2bTNiZXQ3cjdnaQ"),
		testutil.MustParseURL("https://domain1.com"), // Invalid hashlink
	}

	h := &noOpAnchorEventAcknowledgementHandler{}

	require.NoError(t, h.AnchorEventAcknowledged(actor, ref, additionalRefs))
}

func TestAcceptAllActorsAuth_AuthorizeActor(t *testing.T) {
	h := &AcceptAllActorsAuth{}
	require.NotNil(t, h)

	ok, err := h.AuthorizeActor(nil)
	require.NoError(t, err)
	require.True(t, ok)
}
