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

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestNew(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := New(cfg, &mocks.ActivityStore{}, &mocks.Outbox{})
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

	h := New(cfg, &mocks.ActivityStore{}, &mocks.Outbox{})
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
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")
	service3IRI := mustParseURL("http://localhost:8303/services/service3")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	activityStore := memstore.New(cfg.ServiceName)
	ob := mocks.NewOutbox()

	require.NoError(t, activityStore.AddReference(store.Follower, service1IRI, service3IRI))

	h := New(cfg, activityStore, ob, spi.WithAnchorCredentialHandler(anchorCredHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Anchor credential", func(t *testing.T) {
		const cid = "bafkreiarkubvukdidicmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

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

		published := time.Now()

		create := vocab.NewCreateActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, gotActivity[create.ID()])
			mutex.Unlock()

			require.NotNil(t, anchorCredHandler.AnchorCred(cid))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)
		})

		t.Run("Handler error", func(t *testing.T) {
			errExpected := fmt.Errorf("injected anchor cred handler error")

			anchorCredHandler.WithError(errExpected)
			defer func() { anchorCredHandler.WithError(nil) }()

			require.True(t, errors.Is(h.HandleActivity(create), errExpected))
		})
	})

	t.Run("Anchor credential reference", func(t *testing.T) {
		const (
			cid   = "bafkreiarkubvukdidicmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"
			refID = "http://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"
		)

		published := time.Now()

		create := vocab.NewCreateActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(
					vocab.NewAnchorCredentialReference(refID, cid),
				),
			),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithPublishedTime(&published),
		)

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(create))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, gotActivity[create.ID()])
			mutex.Unlock()

			require.NotNil(t, anchorCredHandler.AnchorCred(cid))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)
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

		create := vocab.NewCreateActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeService)))),
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
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")
	service3IRI := mustParseURL("http://localhost:8303/services/service3")
	service4IRI := mustParseURL("http://localhost:8304/services/service4")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	// Add Service2 & Service3 to Service1's store since we haven't implemented actor resolution yet and
	// Service1 needs to retrieve the requesting actors.
	require.NoError(t, as.PutActor(vocab.NewService(service2IRI.String())))
	require.NoError(t, as.PutActor(vocab.NewService(service3IRI.String())))

	followerAuth := mocks.NewFollowerAuth()

	h := New(cfg, as, ob, spi.WithFollowerAuth(followerAuth))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Accept", func(t *testing.T) {
		followerAuth.WithAccept()

		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[follow.ID()])
		mutex.Unlock()

		followers, err := h.store.GetReferences(store.Follower, h.ServiceIRI)
		require.NoError(t, err)
		require.True(t, containsIRI(followers, service2IRI))
		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 1)

		// Post another follow. Should reply with accept since it's already a follower.
		follow = vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[follow.ID()])
		mutex.Unlock()

		require.Len(t, ob.Activities().QueryByType(vocab.TypeAccept), 2)
	})

	t.Run("Reject", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service3IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		followerAuth.WithReject()

		t.Run("Success", func(t *testing.T) {
			require.NoError(t, h.HandleActivity(follow))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.Nil(t, gotActivity[follow.ID()])
			mutex.Unlock()

			followers, err := h.store.GetReferences(store.Follower, h.ServiceIRI)
			require.NoError(t, err)
			require.False(t, containsIRI(followers, service3IRI))
			require.Len(t, ob.Activities().QueryByType(vocab.TypeReject), 1)
		})
	})

	t.Run("No actor in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, h.HandleActivity(follow), "no actor specified in 'Follow' activity")
	})

	t.Run("No object IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, h.HandleActivity(follow),
			"no IRI specified in 'object' field of the 'Follow' activity")
	})

	t.Run("Object IRI does not match target service IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service4IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service4IRI),
			vocab.WithTo(service1IRI),
		)

		require.True(t, errors.Is(h.HandleActivity(follow), store.ErrNotFound))
	})

	t.Run("AuthorizeFollower error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected authorize error")

		followerAuth.WithError(errExpected)

		defer func() {
			followerAuth.WithError(nil)
		}()

		follow := vocab.NewFollowActivity(newActivityID(service3IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := h.HandleActivity(follow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestHandler_HandleAcceptActivity(t *testing.T) {
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := New(cfg, as, ob)
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(accept))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[accept.ID()])
		mutex.Unlock()

		following, err := h.store.GetReferences(store.Following, h.ServiceIRI)
		require.NoError(t, err)
		require.True(t, containsIRI(following, service1IRI))
	})

	t.Run("No actor in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept), "no actor specified in 'Accept' activity")
	})

	t.Run("No Follow activity specified in 'object' field", func(t *testing.T) {
		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no 'Follow' activity specified in the 'object' field of the 'Accept' activity")
	})

	t.Run("Object is not a Follow activity", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"the 'object' field of the 'Accept' activity must be a 'Follow' type")
	})

	t.Run("No actor specified in the Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no actor specified in the original 'Follow' activity of the 'Accept' activity")
	})

	t.Run("Follow actor does not match target service IRI in Accept activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		accept := vocab.NewAcceptActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(accept),
			"should have ignored 'Accept' since actor in the 'Follow' does not match the target service",
		)
	})
}

func TestHandler_HandleRejectActivity(t *testing.T) {
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := New(cfg, as, ob)
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(reject))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[reject.ID()])
		mutex.Unlock()

		following, err := h.store.GetReferences(store.Following, h.ServiceIRI)
		require.NoError(t, err)
		require.True(t, !containsIRI(following, service1IRI))
	})

	t.Run("No actor in Reject activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject), "no actor specified in 'Reject' activity")
	})

	t.Run("No Follow activity specified in 'object' field", func(t *testing.T) {
		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no 'Follow' activity specified in the 'object' field of the 'Reject' activity")
	})

	t.Run("Object is not a Follow activity", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"the 'object' field of the 'Reject' activity must be a 'Follow' type")
	})

	t.Run("No actor specified in the Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(reject),
			"no actor specified in the original 'Follow' activity of the 'Reject' activity")
	})

	t.Run("Follow actor does not match target service IRI in Reject activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(newActivityID(service2IRI),
			vocab.NewObjectProperty(vocab.WithIRI(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service1IRI),
		)

		reject := vocab.NewRejectActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithActivity(follow)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(reject),
			"should have ignored 'Reject' since actor in the 'Follow' does not match the target service",
		)
	})
}

func TestHandler_HandleAnnounceActivity(t *testing.T) {
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	h := New(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, spi.WithAnchorCredentialHandler(anchorCredHandler))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Anchor credential ref - collection (no embedded object)", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), cid)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID()])
		mutex.Unlock()
	})

	t.Run("Anchor credential ref - ordered collection (no embedded object)", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), cid)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithOrderedCollection(
					vocab.NewOrderedCollection(items),
				),
			),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID()])
		mutex.Unlock()
	})

	t.Run("Anchor credential ref (with embedded object)", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		ref, err := vocab.NewAnchorCredentialReferenceWithDocument(newTransactionID(service1IRI),
			cid, vocab.MustUnmarshalToDoc([]byte(anchorCredential1)),
		)
		require.NoError(t, err)

		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithAnchorCredentialReference(ref),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithPublishedTime(&published),
		)

		require.NoError(t, h.HandleActivity(announce))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID()])
		mutex.Unlock()
	})

	t.Run("Anchor credential ref - collection - unsupported object type", func(t *testing.T) {
		items := []*vocab.ObjectProperty{
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
		}

		published := time.Now()

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithCollection(
					vocab.NewCollection(items),
				),
			),
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

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithOrderedCollection(
					vocab.NewOrderedCollection(items),
				),
			),
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

		announce := vocab.NewAnnounceActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(
				vocab.WithActor(service1IRI),
			),
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
	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	witness := mocks.NewWitnessHandler()

	h := New(cfg, memstore.New(cfg.ServiceName), &mocks.Outbox{}, spi.WithWitness(witness))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity[activity.ID()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
		witness.WithProof([]byte(proof))

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

		require.NoError(t, h.HandleActivity(offer))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[offer.ID()])
		mutex.Unlock()
		require.Len(t, witness.AnchorCreds(), 1)

		liked, err := h.store.GetReferences(store.Liked, h.ServiceIRI)
		require.NoError(t, err)
		require.NotEmpty(t, liked)
	})

	t.Run("No response from witness -> error", func(t *testing.T) {
		witness.WithProof(nil)

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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(vocab.WithObject(vocab.NewObject(vocab.WithType(vocab.TypeAnnounce)))),
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

		offer := vocab.NewOfferActivity(newActivityID(service1IRI),
			vocab.NewObjectProperty(),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
		)

		err := h.HandleActivity(offer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "object is required")
	})
}

func newActivityID(id fmt.Stringer) string {
	return fmt.Sprintf("%s/%s", id, uuid.New())
}

func newTransactionID(id fmt.Stringer) string {
	return fmt.Sprintf("%s/%s", id, uuid.New())
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
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
