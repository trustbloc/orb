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

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
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

const pageSize = 2

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

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(undeliverableHandler))
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
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(undeliverableHandler))
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

	ob, err := New(cfg, activityStore, pubSub, transport.Default(),
		&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(undeliverableHandler))
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

	httpServer := httpserver.New(":8003", "", "", "",
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

	ob, err := New(cfg, activityStore, pubSub, transport.Default(),
		&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(undeliverableHandler))
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
			testutil.MustParseURL(vocab.PublicIRI),
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
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, spi.ErrNotStarted))
		require.Nil(t, activityID)
	})

	t.Run("AddActivity error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &mocks.ActivityStore{}
		activityStore.AddActivityReturns(errExpected)

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, activityID)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("AddReference error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &mocks.ActivityStore{}
		activityStore.AddReferenceReturns(errExpected)

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, activityID)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Marshal error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		errExpected := errors.New("injected marshal error")

		ob.jsonMarshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		activity := vocab.NewCreateActivity(nil)

		activityID, err := ob.Post(activity)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, activityID)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Redelivery max retries reached", func(t *testing.T) {
		undeliverableHandler := mocks.NewUndeliverableHandler()

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(undeliverableHandler))
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
			vocab.WithTo(service2URL),
		)

		activityID, err := ob.Post(activity)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(1000 * time.Millisecond)

		undeliverableActivities := undeliverableHandler.Activities()
		require.Len(t, undeliverableActivities, 1)
		require.Equal(t, activity.ID(), undeliverableActivities[0].Activity.ID())

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Redelivery unmarshal error", func(t *testing.T) {
		pubSub := mocks.NewPubSub()

		ob, err := New(cfg, activityStore, pubSub, transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		errExpected := errors.New("injected unmarshal error")

		ob.jsonUnmarshal = func(data []byte, v interface{}) error { return errExpected }

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithTo(service2URL),
		)

		activityID, err := ob.Post(activity)
		require.NoError(t, err)
		require.NotNil(t, activityID)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Handler error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected handler error")

		handler := &mocks.ActivityHandler{}
		handler.HandleActivityReturns(errExpected)

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			handler, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
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
			vocab.WithTo(service2URL),
		)

		activityID, err := ob.Post(activity)

		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, activityID)

		ob.Stop()
	})

	t.Run("Invalid actor error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), transport.Default(),
			&mocks.ActivityHandler{}, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
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
		require.Nil(t, activityID)

		ob.Stop()
	})
}

func TestDeduplicate(t *testing.T) {
	service1URL := testutil.MustParseURL("http://localhost:8002/services/service1")
	service2URL := testutil.MustParseURL("http://localhost:8002/services/service2")

	require.Len(t, deduplicate([]*url.URL{service1URL, service2URL, service1URL, service2URL}), 2)
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

func handleMockCollection(t *testing.T, collID *url.URL, uris []*url.URL, w http.ResponseWriter, req *http.Request) {
	t.Logf("Got request for %s without paging\n", req.URL.Path)

	respBytes, err := json.Marshal(aptestutil.NewMockCollection(
		collID,
		testutil.NewMockID(collID, "?page=true"),
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

	respBytes, err := json.Marshal(aptestutil.NewMockCollectionPage(id, next, collID,
		len(uris), uris[from:to]...,
	))
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(respBytes)
	require.NoError(t, err)
}
