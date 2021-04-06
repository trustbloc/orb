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
	clientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const cid = "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

var (
	host1        = testutil.MustParseURL("https://sally.example.com")
	anchorCredID = testutil.NewMockID(host1, "/transactions/bafkreihwsn")
)

func TestNewInbox(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &clientmocks.HTTPClient{})
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

	h := NewOutbox(cfg, &mocks.ActivityStore{}, &clientmocks.HTTPClient{})
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

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &clientmocks.HTTPClient{})
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
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	anchorCredHandler := mocks.NewAnchorCredentialHandler()

	activityStore := memstore.New(cfg.ServiceName)
	ob := mocks.NewOutbox()

	require.NoError(t, activityStore.AddReference(store.Follower, service1IRI, service3IRI))

	h := NewInbox(cfg, activityStore, ob, &clientmocks.HTTPClient{}, spi.WithAnchorCredentialHandler(anchorCredHandler))
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Anchor credential", func(t *testing.T) {
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

			mutex.Lock()
			require.NotNil(t, gotActivity[create.ID().String()])
			mutex.Unlock()

			require.NotNil(t, anchorCredHandler.AnchorCred(anchorCredID.String()))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorCredID)))
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
					vocab.NewAnchorCredentialReference(refID, anchorCredID, cid),
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

			mutex.Lock()
			require.NotNil(t, gotActivity[create.ID().String()])
			mutex.Unlock()

			require.NotNil(t, anchorCredHandler.AnchorCred(anchorCredID.String()))
			require.True(t, len(ob.Activities().QueryByType(vocab.TypeAnnounce)) > 0)

			it, err := activityStore.QueryReferences(store.Share, store.NewCriteria(store.WithObjectIRI(anchorCredID)))
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

	followerAuth := mocks.NewFollowerAuth()

	httpClient := &clientmocks.HTTPClient{}
	httpClient.DoReturns(nil, client.ErrNotFound)

	h := NewInbox(cfg, as, ob, httpClient, spi.WithFollowerAuth(followerAuth))
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

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

		mutex.Lock()
		require.NotNil(t, gotActivity[follow.ID().String()])
		mutex.Unlock()

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

		mutex.Lock()
		require.NotNil(t, gotActivity[follow.ID().String()])
		mutex.Unlock()

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

			mutex.Lock()
			require.Nil(t, gotActivity[follow.ID().String()])
			mutex.Unlock()

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

		require.EqualError(t, h.HandleActivity(follow), "no actor specified in 'Follow' activity")
	})

	t.Run("No object IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, h.HandleActivity(follow),
			"no IRI specified in 'object' field of the 'Follow' activity")
	})

	t.Run("Object IRI does not match target service IRI in Follow activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service3IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.NoError(t, h.HandleActivity(follow))
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

	t.Run("AuthorizeFollower error", func(t *testing.T) {
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

func TestHandler_HandleAcceptActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")

	cfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()
	as := memstore.New(cfg.ServiceName)

	h := NewInbox(cfg, as, ob, &clientmocks.HTTPClient{})
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
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

		mutex.Lock()
		require.NotNil(t, gotActivity[accept.ID().String()])
		mutex.Unlock()

		it, err := h.store.QueryReferences(store.Following, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
		require.NoError(t, err)

		following, err := storeutil.ReadReferences(it, -1)
		require.NoError(t, err)

		require.True(t, containsIRI(following, service1IRI))
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

	t.Run("No Follow activity specified in 'object' field", func(t *testing.T) {
		accept := vocab.NewAcceptActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service1IRI)),
			vocab.WithActor(service1IRI),
			vocab.WithTo(service2IRI),
		)

		require.EqualError(t, h.HandleActivity(accept),
			"no 'Follow' activity specified in the 'object' field of the 'Accept' activity")
	})

	t.Run("Object is not a Follow activity", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
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
			"the 'object' field of the 'Accept' activity must be a 'Follow' type")
	})

	t.Run("No actor specified in the Follow activity", func(t *testing.T) {
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
			"no actor specified in the original 'Follow' activity of the 'Accept' activity")
	})

	t.Run("Follow actor does not match target service IRI in Accept activity", func(t *testing.T) {
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

		require.NoError(t, h.HandleActivity(accept),
			"should have ignored 'Accept' since actor in the 'Follow' does not match the target service",
		)
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

	h := NewInbox(cfg, as, ob, &clientmocks.HTTPClient{})
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
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

		mutex.Lock()
		require.NotNil(t, gotActivity[reject.ID().String()])
		mutex.Unlock()

		it, err := h.store.QueryReferences(store.Following, store.NewCriteria(store.WithObjectIRI(h.ServiceIRI)))
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
			"no 'Follow' activity specified in the 'object' field of the 'Reject' activity")
	})

	t.Run("Object is not a Follow activity", func(t *testing.T) {
		follow := vocab.NewAnnounceActivity(
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
			"the 'object' field of the 'Reject' activity must be a 'Follow' type")
	})

	t.Run("No actor specified in the Follow activity", func(t *testing.T) {
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
			"no actor specified in the original 'Follow' activity of the 'Reject' activity")
	})

	t.Run("Follow actor does not match target service IRI in Reject activity", func(t *testing.T) {
		follow := vocab.NewFollowActivity(
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

		require.NoError(t, h.HandleActivity(reject),
			"should have ignored 'Reject' since actor in the 'Follow' does not match the target service",
		)
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

	h := NewInbox(cfg, &mocks.ActivityStore{}, &mocks.Outbox{}, &clientmocks.HTTPClient{},
		spi.WithAnchorCredentialHandler(anchorCredHandler))
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Anchor credential ref - collection (no embedded object)", func(t *testing.T) {
		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), anchorCredID, cid)

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

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID().String()])
		mutex.Unlock()
	})

	t.Run("Anchor credential ref - ordered collection (no embedded object)", func(t *testing.T) {
		ref := vocab.NewAnchorCredentialReference(newTransactionID(service1IRI), anchorCredID, cid)

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

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID().String()])
		mutex.Unlock()
	})

	t.Run("Anchor credential ref (with embedded object)", func(t *testing.T) {
		ref, err := vocab.NewAnchorCredentialReferenceWithDocument(newTransactionID(service1IRI),
			anchorCredID, cid, vocab.MustUnmarshalToDoc([]byte(anchorCredential1)),
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

		mutex.Lock()
		require.NotNil(t, gotActivity[announce.ID().String()])
		mutex.Unlock()
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

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	witness := mocks.NewWitnessHandler()

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), &mocks.Outbox{}, &clientmocks.HTTPClient{}, spi.WithWitness(witness))
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

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

		mutex.Lock()
		require.NotNil(t, gotActivity[offer.ID().String()])
		mutex.Unlock()
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

	h := NewInbox(cfg, memstore.New(cfg.ServiceName), &mocks.Outbox{}, &clientmocks.HTTPClient{},
		spi.WithProofHandler(proofHandler))
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
			gotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(proof)))
		require.NoError(t, err)

		startTime := time.Now()
		endTime := startTime.Add(time.Hour)

		anchorCredID := newTransactionID(h.ServiceIRI)

		like := vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(anchorCredID)),
			vocab.WithID(h.newActivityID()),
			vocab.WithActor(h.ServiceIRI),
			vocab.WithTo(service2IRI),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)

		require.NoError(t, h.HandleActivity(like))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.NotNil(t, gotActivity[like.ID().String()])
		mutex.Unlock()

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
			vocab.WithID(h.newActivityID()),
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
			vocab.WithID(h.newActivityID()),
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
			vocab.WithID(h.newActivityID()),
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
			vocab.WithID(h.newActivityID()),
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
			vocab.WithID(h.newActivityID()),
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

func TestHandler_HandleUndoActivity(t *testing.T) {
	service1IRI := testutil.MustParseURL("http://localhost:8301/services/service1")
	service2IRI := testutil.MustParseURL("http://localhost:8302/services/service2")
	service3IRI := testutil.MustParseURL("http://localhost:8303/services/service3")

	inboxCfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1IRI,
	}

	outboxCfg := &Config{
		ServiceName: "service2",
		ServiceIRI:  service2IRI,
	}

	ob := mocks.NewOutbox()

	httpClient := &clientmocks.HTTPClient{}
	httpClient.DoReturns(nil, client.ErrNotFound)

	inboxHandler := NewInbox(inboxCfg, memstore.New(inboxCfg.ServiceName), ob, httpClient)
	require.NotNil(t, inboxHandler)

	inboxHandler.Start()
	defer inboxHandler.Stop()

	outboxHandler := NewOutbox(outboxCfg, memstore.New(outboxCfg.ServiceName), httpClient)
	require.NotNil(t, outboxHandler)

	inboxHandler.Start()
	defer inboxHandler.Stop()

	inboxActivityChan := inboxHandler.Subscribe()
	outboxActivityChan := outboxHandler.Subscribe()

	var (
		mutex             sync.Mutex
		inboxGotActivity  = make(map[string]*vocab.ActivityType)
		outboxGotActivity = make(map[string]*vocab.ActivityType)
	)

	go func() {
		for activity := range inboxActivityChan {
			mutex.Lock()
			inboxGotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

	go func() {
		for activity := range outboxActivityChan {
			mutex.Lock()
			outboxGotActivity[activity.ID().String()] = activity
			mutex.Unlock()
		}
	}()

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
		vocab.WithID(inboxHandler.newActivityID()),
		vocab.WithActor(service2IRI),
		vocab.WithTo(service1IRI),
	)

	require.NoError(t, outboxHandler.store.AddActivity(follow))
	require.NoError(t, outboxHandler.store.AddActivity(followNoIRI))
	require.NoError(t, outboxHandler.store.AddActivity(followActorNotLocalService))

	require.NoError(t, inboxHandler.store.PutActor(vocab.NewService(service2IRI)))
	require.NoError(t, inboxHandler.store.AddActivity(follow))
	require.NoError(t, inboxHandler.store.AddActivity(followNoIRI))
	require.NoError(t, inboxHandler.store.AddActivity(followIRINotLocalService))
	require.NoError(t, inboxHandler.store.AddActivity(unsupported))

	t.Run("No actor in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, inboxHandler.HandleActivity(undo), "no actor specified in 'Undo' activity")
	})

	t.Run("No object IRI in activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		require.EqualError(t, inboxHandler.HandleActivity(undo),
			"no IRI specified in 'object' field of the 'Undo' activity")
	})

	t.Run("Activity not found in storage", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(newActivityID(service3IRI))),
			vocab.WithID(newActivityID(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service1IRI),
		)

		err := inboxHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), store.ErrNotFound.Error())
	})

	t.Run("Actor of Undo does not match the actor in Follow activity", func(t *testing.T) {
		undo := vocab.NewUndoActivity(
			vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
			vocab.WithActor(service3IRI),
			vocab.WithTo(service1IRI),
		)

		err := inboxHandler.HandleActivity(undo)
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

		err := inboxHandler.HandleActivity(undo)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not supported")
	})

	t.Run("Inbox Undo Follow", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, inboxHandler.store.AddReference(store.Follower, service1IRI, service2IRI))

			it, err := inboxHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(inboxHandler.ServiceIRI)))
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

			require.NoError(t, inboxHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, inboxGotActivity[undo.ID().String()])
			mutex.Unlock()

			it, err = inboxHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(inboxHandler.ServiceIRI)))
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

			require.EqualError(t, inboxHandler.HandleActivity(undo),
				"no IRI specified in 'object' field of the 'Follow' activity")
		})

		t.Run("IRI not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followIRINotLocalService.ID().URL())),
				vocab.WithID(newActivityID(service2IRI)),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, inboxHandler.HandleActivity(undo))
		})

		t.Run("Not a follower", func(t *testing.T) {
			it, err := inboxHandler.store.QueryReferences(store.Follower,
				store.NewCriteria(store.WithObjectIRI(inboxHandler.ServiceIRI)))
			require.NoError(t, err)

			followers, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.False(t, containsIRI(followers, service2IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, inboxHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, inboxGotActivity[undo.ID().String()])
			mutex.Unlock()
		})
	})

	t.Run("Outbox Undo Follow", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			require.NoError(t, outboxHandler.store.AddReference(store.Following, service2IRI, service1IRI))

			it, err := outboxHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(outboxHandler.ServiceIRI)))
			require.NoError(t, err)

			following, err := storeutil.ReadReferences(it, -1)
			require.NoError(t, err)

			require.True(t, containsIRI(following, service1IRI))

			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(follow.ID().URL())),
				vocab.WithActor(service2IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, outboxHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, outboxGotActivity[undo.ID().String()])
			mutex.Unlock()

			it, err = outboxHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(outboxHandler.ServiceIRI)))
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

			require.EqualError(t, outboxHandler.HandleActivity(undo),
				"no IRI specified in 'object' field of the 'Follow' activity")
		})

		t.Run("Actor not local service -> error", func(t *testing.T) {
			undo := vocab.NewUndoActivity(
				vocab.NewObjectProperty(vocab.WithIRI(followActorNotLocalService.ID().URL())),
				vocab.WithActor(service3IRI),
				vocab.WithTo(service1IRI),
			)

			require.NoError(t, outboxHandler.HandleActivity(undo))
		})

		t.Run("Not following", func(t *testing.T) {
			it, err := outboxHandler.store.QueryReferences(store.Following,
				store.NewCriteria(store.WithObjectIRI(inboxHandler.ServiceIRI)))
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

			require.NoError(t, outboxHandler.HandleActivity(undo))

			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			require.NotNil(t, outboxGotActivity[undo.ID().String()])
			mutex.Unlock()
		})
	})
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
