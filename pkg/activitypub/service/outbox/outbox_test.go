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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNewOutbox(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")

	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")

	t.Run("Success", func(t *testing.T) {
		cfg := &Config{
			ServiceName: "service1",
			ServiceIRI:  service1URL,
			Topic:       "activities",
		}

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), &http.Client{},
			spi.WithUndeliverableHandler(undeliverableHandler))
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

		ob, err := New(cfg, activityStore, mocks.NewPubSub().WithError(errExpected), &http.Client{},
			spi.WithUndeliverableHandler(undeliverableHandler))
		require.Error(t, err)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, ob)
	})
}

func TestOutbox_StartStop(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")

	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
	}

	ob, err := New(cfg, activityStore, pubSub, &http.Client{}, spi.WithUndeliverableHandler(undeliverableHandler))
	require.NoError(t, err)
	require.NotNil(t, ob)

	ob.Start()

	time.Sleep(50 * time.Millisecond)

	require.Equal(t, spi.StateStarted, ob.State())

	ob.Stop()

	require.Equal(t, spi.StateStopped, ob.State())
}

func TestOutbox_Post(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)
	log.SetLevel("activitypub_client", log.DEBUG)

	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8003/services/service2")

	var mutex sync.RWMutex

	activitiesReceived2 := make(map[string]*vocab.ActivityType)

	receivedActivity := func(activity *vocab.ActivityType, activities map[string]*vocab.ActivityType) {
		mutex.Lock()
		activities[activity.ID().String()] = activity
		mutex.Unlock()
	}

	httpServer := httpserver.New(":8003", "", "", "",
		newTestHandler("/services/service2", http.MethodGet, mockServiceRequestHandler(t, service2URL)),
		newTestHandler("/services/service2/inbox", http.MethodPost,
			mockInboxHandler(t, func(activity *vocab.ActivityType) {
				receivedActivity(activity, activitiesReceived2)
			}),
		),
	)

	require.NoError(t, httpServer.Start())

	defer func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}()

	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	require.NoError(t, activityStore.AddReference(store.Follower, service1URL, service2URL))

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
		RedeliveryConfig: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.5,
			MaxMessages:    20,
		},
	}

	ob, err := New(cfg, activityStore, pubSub, &http.Client{}, spi.WithUndeliverableHandler(undeliverableHandler))
	require.NoError(t, err)
	require.NotNil(t, ob)

	ob.Start()

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName),
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(
					vocab.WithIRI(objIRI),
				),
			),
		),
		vocab.WithTo(
			testutil.MustParseURL(vocab.PublicIRI),
			service2URL,
			service1URL, // Should ignore this IRI since it's the local service
		),
	)

	require.NoError(t, ob.Post(activity))

	time.Sleep(250 * time.Millisecond)

	mutex.RLock()
	_, ok := activitiesReceived2[activity.ID().String()]
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
	require.Equal(t, 1, it.TotalItems())

	time.Sleep(100 * time.Millisecond)

	ob.Stop()
}

func TestOutbox_PostError(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8002/services/service2")

	activityStore := memstore.New("service1")

	require.NoError(t, activityStore.PutActor(aptestutil.NewMockService(service2URL)))

	cfg := &Config{
		ServiceName: "service1",
		ServiceIRI:  service1URL,
		Topic:       "activities",
		RedeliveryConfig: &redelivery.Config{
			MaxRetries:     1,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.5,
			MaxMessages:    20,
		},
	}

	objIRI := testutil.MustParseURL("http://example.com/transactions/txn1")

	t.Run("Not started", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), &http.Client{},
			spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName), nil)

		require.True(t, errors.Is(ob.Post(activity), spi.ErrNotStarted))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &mocks.ActivityStore{}
		activityStore.AddActivityReturns(errExpected)

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), &http.Client{},
			spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName), nil)

		require.True(t, errors.Is(ob.Post(activity), errExpected))

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Marshal error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), &http.Client{},
			spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		errExpected := errors.New("injected marshal error")

		ob.jsonMarshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName), nil)

		require.True(t, errors.Is(ob.Post(activity), errExpected))

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Redelivery max retries reached", func(t *testing.T) {
		undeliverableHandler := mocks.NewUndeliverableHandler()

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), &http.Client{},
			spi.WithUndeliverableHandler(undeliverableHandler))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithTo(service2URL),
		)

		require.NoError(t, ob.Post(activity))

		time.Sleep(1000 * time.Millisecond)

		undeliverableActivities := undeliverableHandler.Activities()
		require.Len(t, undeliverableActivities, 1)
		require.Equal(t, activity.ID(), undeliverableActivities[0].Activity.ID())

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Redelivery unmarshal error", func(t *testing.T) {
		pubSub := mocks.NewPubSub()

		ob, err := New(cfg, activityStore, pubSub, &http.Client{},
			spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		errExpected := errors.New("injected unmarshal error")

		ob.jsonUnmarshal = func(data []byte, v interface{}) error { return errExpected }

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithTo(service2URL),
		)

		require.NoError(t, ob.Post(activity))

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})
}

func newActivityID(serviceName string) *url.URL {
	return testutil.MustParseURL(fmt.Sprintf("%s/%s", serviceName, uuid.New()))
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

func mockServiceRequestHandler(t *testing.T, iri *url.URL) common.HTTPRequestHandler {
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
