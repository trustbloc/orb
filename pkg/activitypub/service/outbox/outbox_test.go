/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	storemocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/lifecycle"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

//nolint:lll
//go:generate counterfeiter -o ../mocks/referenceiterator.gen.go --fake-name ReferenceIterator ./../../client ReferenceIterator

const pageSize = 2

func TestNewOutbox(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")

	activityStore := memstore.New("service1")

	t.Run("Success", func(t *testing.T) {
		cfg := &Config{
			ServiceName: "service1",
			ServiceIRI:  service1URL,
			Topic:       "activities",
		}

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)
	})

	t.Run("PubSub Subscribe error", func(t *testing.T) {
		cfg := &Config{
			ServiceName: "service1",
			ServiceIRI:  service1URL,
			Topic:       "activities",
		}

		errExpected := errors.New("injected PubSub error")

		ob, err := New(cfg, activityStore, mocks.NewPubSub().WithError(errExpected), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.Error(t, err)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, ob)
	})
}

func TestOutbox_StartStop(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")

	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
	}

	ob, err := New(cfg, activityStore, pubSub, transport.Default(),
		&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
	require.NoError(t, err)
	require.NotNil(t, ob)

	ob.Start()

	time.Sleep(50 * time.Millisecond)

	require.Equal(t, lifecycle.StateStarted, ob.State())

	ob.Stop()

	require.Equal(t, lifecycle.StateStopped, ob.State())
}

func TestOutbox_Post(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)
	log.SetLevel("activitypub_client", log.DEBUG)

	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8003/services/service2")
	service3URL := testutil.MustParseURL("http://localhost:8003/services/service3")
	service4URL := testutil.MustParseURL("http://localhost:8003/services/service4")
	service5URL := testutil.MustParseURL("http://localhost:8003/services/service5")

	witnesses := []*url.URL{service3URL, service4URL, service5URL}

	var mutex sync.RWMutex

	activitiesReceived2 := make(map[string]*vocab.ActivityType)
	activitiesReceived3 := make(map[string]*vocab.ActivityType)
	activitiesReceived4 := make(map[string]*vocab.ActivityType)
	activitiesReceived5 := make(map[string]*vocab.ActivityType)

	receivedActivity := func(activity *vocab.ActivityType, activities map[string]*vocab.ActivityType) {
		mutex.Lock()
		activities[activity.ID().String()] = activity
		mutex.Unlock()
	}

	httpServer := httpserver.New(":8003", "", "", 1*time.Second,
		&mockService{}, &mockService{}, &mockService{},
		newTestHandler("/services/service2", http.MethodGet, mockServiceRequestHandler(t, service2URL)),
		newTestHandler("/services/service3", http.MethodGet, mockServiceRequestHandler(t, service3URL)),
		newTestHandler("/services/service4", http.MethodGet, mockServiceRequestHandler(t, service4URL)),
		newTestHandler("/services/service5", http.MethodGet, mockServiceRequestHandler(t, service5URL)),
		newTestHandler("/services/service2/witnesses", http.MethodGet,
			func(w http.ResponseWriter, req *http.Request) {
				collID := testutil.NewMockID(service2URL, resthandler.WitnessesPath)

				if !paramAsBool(req, "page") {
					handleMockCollection(t, collID, witnesses, w, req)
				} else {
					handleMockCollectionPage(t, collID, witnesses, w, req)
				}
			},
		),
		newTestHandler("/services/service2/inbox", http.MethodPost,
			mockInboxHandler(t, func(activity *vocab.ActivityType) {
				receivedActivity(activity, activitiesReceived2)
			}),
		),
		newTestHandler("/services/service3/inbox", http.MethodPost,
			mockInboxHandler(t, func(activity *vocab.ActivityType) {
				receivedActivity(activity, activitiesReceived3)
			}),
		),
		newTestHandler("/services/service4/inbox", http.MethodPost,
			mockInboxHandler(t, func(activity *vocab.ActivityType) {
				receivedActivity(activity, activitiesReceived4)
			}),
		),
		newTestHandler("/services/service5/inbox", http.MethodPost,
			mockInboxHandler(t, func(activity *vocab.ActivityType) {
				receivedActivity(activity, activitiesReceived5)
			}),
		),
	)

	require.NoError(t, httpServer.Start())

	defer func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}()

	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	require.NoError(t, activityStore.AddReference(store.Follower, service1URL, service2URL))

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
	}

	ob, err := New(cfg, activityStore, pubSub, transport.Default(),
		&mocks.ActivityHandler{}, client.New(client.Config{}, transport.Default()), &mocks.WebFingerResolver{},
		&orbmocks.MetricsProvider{})
	require.NoError(t, err)
	require.NotNil(t, ob)

	ob.Start()

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	activity := vocab.NewCreateActivity(
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(
					vocab.WithIRI(objIRI),
				),
			),
		),
		vocab.WithTo(
			vocab.PublicIRI,
			testutil.NewMockID(service1URL, resthandler.FollowersPath),
			testutil.NewMockID(service1URL, resthandler.WitnessesPath),
			testutil.NewMockID(service2URL, resthandler.WitnessesPath),
			service1URL, // Should ignore this IRI since it's the local service
		),
	)

	activityID, err := ob.Post(activity)
	require.NoError(t, err)
	require.NotNil(t, activityID)

	time.Sleep(250 * time.Millisecond)

	mutex.RLock()
	_, ok := activitiesReceived2[activity.ID().String()]
	require.True(t, ok)
	_, ok = activitiesReceived3[activity.ID().String()]
	require.True(t, ok)
	_, ok = activitiesReceived4[activity.ID().String()]
	require.True(t, ok)
	_, ok = activitiesReceived5[activity.ID().String()]
	require.True(t, ok)
	mutex.RUnlock()

	a, err := activityStore.GetActivity(activity.ID().URL())
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equalf(t, activity.ID(), a.ID(), "The activity should have been stored in the outbox")

	it, err := activityStore.QueryReferences(store.Outbox,
		store.NewCriteria(
			store.WithObjectIRI(cfg.ServiceIRI),
			store.WithReferenceIRI(activity.ID().URL()),
		),
	)
	require.NoError(t, err)
	require.NotNil(t, it)

	totalItems, err := it.TotalItems()
	require.NoError(t, err)

	require.Equal(t, 1, totalItems)

	time.Sleep(100 * time.Millisecond)

	ob.Stop()
}

func TestOutbox_PostError(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8002/services/service2")

	activityStore := memstore.New("service1")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
	}

	objIRI := testutil.MustParseURL("http://example.com/transactions/txn1")

	t.Run("Not started", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, lifecycle.ErrNotStarted))
		require.Nil(t, activityID)
	})

	t.Run("Marshal error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		errExpected := errors.New("injected marshal error")

		ob.jsonMarshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, errExpected))
		require.True(t, orberrors.IsBadRequest(err))
		require.Nil(t, activityID)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Invalid actor error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithActor(service2URL),
			vocab.WithTo(service2URL),
		)

		activityID, err := ob.Post(activity)

		require.Error(t, err)
		require.EqualError(t, err, "invalid actor IRI")
		require.True(t, orberrors.IsBadRequest(err))
		require.Nil(t, activityID)

		ob.Stop()
	})
}

func TestOutbox_Handle(t *testing.T) {
	service1URL := testutil.MustParseURL("http://domain1.com/services/orb")
	service2URL := testutil.MustParseURL("http://domain2.com/services/orb")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "outbox",
	}

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	activity := vocab.NewCreateActivity(
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(
					vocab.WithIRI(objIRI),
				),
			),
		),
		vocab.WithID(aptestutil.NewActivityID(service1URL)),
		vocab.WithTo(
			vocab.PublicIRI,
			service2URL,
		),
	)

	t.Run("activity message type", func(t *testing.T) {
		activityMsg := &activityMessage{
			Type:     broadcastType,
			Activity: activity,
		}

		msgBytes, err := json.Marshal(activityMsg)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), msgBytes)

		t.Run("success", func(t *testing.T) {
			ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			require.NotPanics(t, func() { ob.handle(msg) })
		})

		t.Run("persistent error", func(t *testing.T) {
			errExpected := errors.New("injected persistent error")

			activityStore := &mocks.ActivityStore{}
			activityStore.AddActivityReturns(errExpected)

			ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			require.NotPanics(t, func() { ob.handle(msg) })
		})

		t.Run("transient error", func(t *testing.T) {
			errExpected := orberrors.NewTransientf("injected transient error")

			activityStore := &mocks.ActivityStore{}
			activityStore.AddActivityReturns(errExpected)

			ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			require.NotPanics(t, func() { ob.handle(msg) })
		})
	})
}

func TestOutbox_HandleActivityMessage(t *testing.T) {
	service1URL := testutil.MustParseURL("http://domain1.com/services/orb")
	service2URL := testutil.MustParseURL("http://domain2.com/services/orb")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "outbox",
	}

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	activity := vocab.NewCreateActivity(
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(
					vocab.WithIRI(objIRI),
				),
			),
		),
		vocab.WithID(aptestutil.NewActivityID(service1URL)),
		vocab.WithTo(
			vocab.PublicIRI,
			service2URL,
		),
	)

	t.Run("unmarshal error", func(t *testing.T) {
		msg := message.NewMessage(watermill.NewUUID(), []byte(`}`))

		ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)

		a, err := ob.handleActivityMsg(msg)
		require.Error(t, err)
		require.Nil(t, a)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("activity message type", func(t *testing.T) {
		activityMsg := &activityMessage{
			Type:     broadcastType,
			Activity: activity,
		}

		msgBytes, err := json.Marshal(activityMsg)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), msgBytes)

		t.Run("success", func(t *testing.T) {
			ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			a, err := ob.handleActivityMsg(msg)
			require.NoError(t, err)
			require.NotNil(t, a)
			require.Equal(t, activity.ID().String(), a.ID().String())
		})

		t.Run("storage error", func(t *testing.T) {
			errExpected := errors.New("injected storage error")

			activityStore := &mocks.ActivityStore{}
			activityStore.AddActivityReturns(errExpected)

			ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			a, err := ob.handleActivityMsg(msg)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
			require.Nil(t, a)
		})

		t.Run("handler error", func(t *testing.T) {
			errExpected := errors.New("injected handler error")

			handler := &mocks.ActivityHandler{}
			handler.HandleActivityReturns(errExpected)

			ob, err := New(cfg, &mocks.ActivityStore{}, mocks.NewPubSub(), transport.Default(),
				handler, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			a, err := ob.handleActivityMsg(msg)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
			require.Nil(t, a)
		})

		t.Run("resolve error", func(t *testing.T) {
			t.Run("transient error", func(t *testing.T) {
				errExpected := orberrors.NewTransientf("injected resolver transient error")

				wfResolver := &mocks.WebFingerResolver{}
				wfResolver.Err = errExpected

				ob, err := New(cfg, &mocks.ActivityStore{}, mocks.NewPubSub(), transport.Default(),
					&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), wfResolver, &orbmocks.MetricsProvider{})
				require.NoError(t, err)
				require.NotNil(t, ob)

				a, err := ob.handleActivityMsg(msg)
				require.NoError(t, err)
				require.Equal(t, activity.ID().String(), a.ID().String())
			})

			t.Run("persistent error", func(t *testing.T) {
				errExpected := fmt.Errorf("injected resolver persistent error")

				wfResolver := &mocks.WebFingerResolver{}
				wfResolver.Err = errExpected

				ob, err := New(cfg, &mocks.ActivityStore{}, mocks.NewPubSub(), transport.Default(),
					&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), wfResolver, &orbmocks.MetricsProvider{})
				require.NoError(t, err)
				require.NotNil(t, ob)

				a, err := ob.handleActivityMsg(msg)
				require.NoError(t, err)
				require.Equal(t, activity.ID().String(), a.ID().String())
			})
		})
	})

	t.Run("resolve-and-deliver message type", func(t *testing.T) {
		activityMsg := &activityMessage{
			Type:      resolveAndDeliverType,
			Activity:  activity,
			TargetIRI: vocab.NewURLProperty(service2URL),
		}

		msgBytes, err := json.Marshal(activityMsg)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), msgBytes)

		t.Run("success", func(t *testing.T) {
			apClient := mocks.NewActivitPubClient().WithActor(vocab.NewService(service2URL))

			ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, apClient, &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			a, err := ob.handleActivityMsg(msg)
			require.NoError(t, err)
			require.NotNil(t, a)
			require.Equal(t, activity.ID().String(), a.ID().String())
		})

		t.Run("resolve error", func(t *testing.T) {
			t.Run("transient error", func(t *testing.T) {
				errExpected := orberrors.NewTransientf("injected resolver transient error")

				wfResolver := &mocks.WebFingerResolver{}
				wfResolver.Err = errExpected

				ob, err := New(cfg, &mocks.ActivityStore{}, mocks.NewPubSub(), transport.Default(),
					&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), wfResolver, &orbmocks.MetricsProvider{})
				require.NoError(t, err)
				require.NotNil(t, ob)

				a, err := ob.handleActivityMsg(msg)
				require.Error(t, err)
				require.Contains(t, err.Error(), errExpected.Error())
				require.True(t, orberrors.IsTransient(err))
				require.Nil(t, a)
			})

			t.Run("persistent error", func(t *testing.T) {
				errExpected := fmt.Errorf("injected resolver persistent error")

				wfResolver := &mocks.WebFingerResolver{}
				wfResolver.Err = errExpected

				ob, err := New(cfg, &mocks.ActivityStore{}, mocks.NewPubSub(), transport.Default(),
					&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), wfResolver, &orbmocks.MetricsProvider{})
				require.NoError(t, err)
				require.NotNil(t, ob)

				a, err := ob.handleActivityMsg(msg)
				require.Error(t, err)
				require.Contains(t, err.Error(), errExpected.Error())
				require.True(t, !orberrors.IsTransient(err))
				require.Nil(t, a)
			})
		})
	})

	t.Run("deliver message type", func(t *testing.T) {
		activityMsg := &activityMessage{
			Type:      deliverType,
			Activity:  activity,
			TargetIRI: vocab.NewURLProperty(service2URL),
		}

		msgBytes, err := json.Marshal(activityMsg)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), msgBytes)

		t.Run("marshal error", func(t *testing.T) {
			ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
				&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
			require.NoError(t, err)
			require.NotNil(t, ob)

			errExpected := errors.New("injected marshal error")

			ob.jsonMarshal = func(v interface{}) ([]byte, error) {
				return nil, errExpected
			}

			a, err := ob.handleActivityMsg(msg)
			require.Error(t, err)
			require.Nil(t, a)
			require.Contains(t, err.Error(), errExpected.Error())
		})
	})

	t.Run("unsupported message type", func(t *testing.T) {
		activityMsg := &activityMessage{
			Type: "unsupported",
		}

		msgBytes, err := json.Marshal(activityMsg)
		require.NoError(t, err)

		msg := message.NewMessage(watermill.NewUUID(), msgBytes)

		ob, err := New(cfg, memstore.New("service1"), mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, mocks.NewActivitPubClient(), &mocks.WebFingerResolver{}, &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, ob)

		a, err := ob.handleActivityMsg(msg)
		require.Error(t, err)
		require.Nil(t, a)
		require.Contains(t, err.Error(), "unsupported activity message type [unsupported]")
	})
}

func TestDeduplicate(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8002/services/service2")

	require.Len(t, deduplicateAndFilter([]*url.URL{service1URL, service2URL, service1URL, service2URL}, nil), 2)
	require.Len(t, deduplicateAndFilter([]*url.URL{service1URL, service2URL, service1URL}, []*url.URL{service2URL}), 1)
}

func TestResolveInboxes(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
	}

	apClient := mocks.NewActivitPubClient()

	activityStore := &mocks.ActivityStore{}

	wfResolver := &mocks.WebFingerResolver{}

	ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
		&mocks.ActivityHandler{}, apClient, wfResolver, &orbmocks.MetricsProvider{})
	require.NoError(t, err)
	require.NotNil(t, ob)

	iri1 := testutil.NewMockID(service1URL, resthandler.FollowersPath)
	iri2 := testutil.NewMockID(service1URL, resthandler.WitnessesPath)
	iri3 := testutil.NewMockID(service1URL, "/unsupported")

	const errFormat = "error querying for references of type %s from storage: %s"

	t.Run("Transient error", func(t *testing.T) {
		errTransient := orberrors.NewTransient(errors.New("injected transient error"))

		activityStore.QueryReferencesReturns(nil, errTransient)

		inboxes := ob.resolveInboxes([]*url.URL{iri1, iri2, iri3}, nil)
		require.Len(t, inboxes, 2)

		for _, resp := range inboxes {
			require.Error(t, resp.err)
			require.True(t, orberrors.IsTransient(resp.err))

			switch resp.iri.String() {
			case iri1.String():
				require.EqualError(t, resp.err, fmt.Sprintf(errFormat, "FOLLOWER", errTransient))
			case iri2.String():
				require.EqualError(t, resp.err, fmt.Sprintf(errFormat, "WITNESS", errTransient))
			}
		}
	})

	t.Run("Persistent error", func(t *testing.T) {
		errPersistent := errors.New("injected persistent error")

		activityStore.QueryReferencesReturns(nil, errPersistent)

		inboxes := ob.resolveInboxes([]*url.URL{iri1}, nil)
		require.Len(t, inboxes, 1)
		require.Error(t, inboxes[0].err)
		require.False(t, orberrors.IsTransient(inboxes[0].err))
		require.EqualError(t, inboxes[0].err, fmt.Sprintf(errFormat, "FOLLOWER", errPersistent))
		require.Equal(t, iri1.String(), inboxes[0].iri.String())
	})

	t.Run("WebFinger error", func(t *testing.T) {
		errExpected := orberrors.NewTransientf("injected WebFinger error")
		wfResolver.Err = errExpected

		service2IRI := testutil.MustParseURL("http://orb.domain2.com/services/orb")

		it := &storemocks.ReferenceIterator{}
		it.NextReturnsOnCall(0, service2IRI, nil)
		it.NextReturnsOnCall(1, nil, store.ErrNotFound)

		activityStore.QueryReferencesReturns(it, nil)

		inboxes := ob.resolveInboxes([]*url.URL{iri1}, nil)
		require.Len(t, inboxes, 1)

		inbox := inboxes[0]

		require.Error(t, inbox.err)
		require.Contains(t, inbox.err.Error(), errExpected.Error())
		require.NotNil(t, inbox.iri)
		require.Equal(t, service2IRI.String(), inbox.iri.String())
	})
}

type testHandler struct {
	path    string
	method  string
	handler common.HTTPRequestHandler
}

func newTestHandler(path, method string, handler common.HTTPRequestHandler) *testHandler {
	return &testHandler{
		path:    path,
		method:  method,
		handler: handler,
	}
}

func (m *testHandler) Path() string {
	return m.path
}

func (m *testHandler) Method() string {
	return m.method
}

func (m *testHandler) Handler() common.HTTPRequestHandler {
	return m.handler
}

func paramAsInt(req *http.Request, param string) (int, bool) {
	params := req.URL.Query()

	values := params[param]
	if len(values) == 0 || values[0] == "" {
		return 0, false
	}

	size, err := strconv.Atoi(values[0])
	if err != nil {
		logger.Debugf("Invalid value for parameter [%s]: %s", param, err)

		return 0, false
	}

	return size, true
}

func paramAsBool(req *http.Request, param string) bool {
	params := req.URL.Query()

	values := params[param]
	if len(values) == 0 || values[0] == "" {
		return false
	}

	b, err := strconv.ParseBool(values[0])
	if err != nil {
		logger.Debugf("Invalid value for parameter [%s]: %s", param, err)

		return false
	}

	return b
}

func mockServiceRequestHandler(t *testing.T, iri *url.URL) common.HTTPRequestHandler {
	t.Helper()

	return func(w http.ResponseWriter, req *http.Request) {
		respBytes, err := json.Marshal(aptestutil.NewMockService(iri))
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(respBytes)
		require.NoError(t, err)
	}
}

func mockInboxHandler(t *testing.T, handle func(activity *vocab.ActivityType)) common.HTTPRequestHandler {
	t.Helper()

	return func(w http.ResponseWriter, req *http.Request) {
		bytes, err := ioutil.ReadAll(req.Body)
		require.NoError(t, err)

		fmt.Printf("Got HTTP message: %s\n", bytes)

		activity := &vocab.ActivityType{}
		require.NoError(t, json.Unmarshal(bytes, activity))

		handle(activity)

		w.WriteHeader(http.StatusOK)
	}
}

func handleMockCollection(t *testing.T, collID *url.URL, uris []*url.URL, w http.ResponseWriter, req *http.Request) {
	t.Helper()
	t.Logf("Got request for %s without paging\n", req.URL.Path)

	respBytes, err := json.Marshal(aptestutil.NewMockCollection(
		collID,
		testutil.NewMockID(collID, "?page=true"),
		testutil.NewMockID(collID, "?page=true&page-num=1"),
		len(uris),
	))
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(respBytes)
	require.NoError(t, err)
}

func handleMockCollectionPage(t *testing.T, collID *url.URL, uris []*url.URL,
	w http.ResponseWriter, req *http.Request) {
	t.Helper()

	pageNum, ok := paramAsInt(req, "page-num")
	if !ok {
		pageNum = 0
	}

	t.Logf("Got request for %s for page %d\n", req.URL.Path, pageNum)

	from := pageSize * pageNum
	to := from + pageSize

	if to > len(uris) {
		to = len(uris)
	}

	var next *url.URL

	id := testutil.NewMockID(collID, fmt.Sprintf("?page=true&page-num=%d", pageNum))

	if len(uris) > pageSize*(pageNum+1) {
		next = testutil.NewMockID(collID, fmt.Sprintf("?page=true&page-num=%d", pageNum+1))
	}

	var items []*vocab.ObjectProperty
	for _, uri := range uris[from:to] {
		items = append(items, vocab.NewObjectProperty(vocab.WithIRI(uri)))
	}

	respBytes, err := json.Marshal(aptestutil.NewMockCollectionPage(id, next, nil, collID,
		len(uris), items...,
	))
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(respBytes)
	require.NoError(t, err)
}

type mockService struct {
	isConnectedErr error
	healthCheckErr error
	pingErr        error
}

func (m *mockService) IsConnected() error {
	return m.isConnectedErr
}

func (m *mockService) HealthCheck() error {
	return m.healthCheckErr
}

func (m *mockService) Ping() error {
	return m.pingErr
}
