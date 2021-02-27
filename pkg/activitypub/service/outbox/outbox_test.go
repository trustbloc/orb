/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outbox

import (
	"context"
	"crypto/tls"
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
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
)

func TestNewOutbox(t *testing.T) {
	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")

	t.Run("Success", func(t *testing.T) {
		cfg := &Config{
			ServiceName:    "service1",
			Topic:          "activities",
			PublishTimeout: 50 * time.Millisecond,
		}

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), undeliverableHandler)
		require.NoError(t, err)
		require.NotNil(t, ob)
	})

	t.Run("Tls HTTP client -> Success", func(t *testing.T) {
		cfg := &Config{
			ServiceName:    "service1",
			Topic:          "activities",
			PublishTimeout: 50 * time.Millisecond,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), undeliverableHandler)
		require.NoError(t, err)
		require.NotNil(t, ob)
	})

	t.Run("PubSub Subscribe error", func(t *testing.T) {
		cfg := &Config{
			ServiceName:    "service1",
			Topic:          "activities",
			PublishTimeout: 50 * time.Millisecond,
		}

		errExpected := errors.New("injected PubSub error")

		ob, err := New(cfg, activityStore, mocks.NewPubSub().WithError(errExpected), undeliverableHandler)
		require.Error(t, err)
		require.True(t, errors.Is(err, errExpected))
		require.Nil(t, ob)
	})
}

func TestOutbox_StartStop(t *testing.T) {
	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	cfg := &Config{
		ServiceName:    "service1",
		Topic:          "activities",
		PublishTimeout: 50 * time.Millisecond,
	}

	ob, err := New(cfg, activityStore, pubSub, undeliverableHandler)
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

	var mutex sync.RWMutex

	activitiesReceived := make(map[string]*vocab.ActivityType)

	httpServer := httpserver.New(":8002", "", "", "",
		newTestHandler("/services/service1", func(w http.ResponseWriter, req *http.Request) {
			bytes, err := ioutil.ReadAll(req.Body)
			require.NoError(t, err)

			fmt.Printf("Got HTTP message: %s\n", bytes)

			activity := &vocab.ActivityType{}
			require.NoError(t, json.Unmarshal(bytes, activity))

			mutex.Lock()
			activitiesReceived[activity.ID()] = activity
			mutex.Unlock()

			w.WriteHeader(http.StatusOK)
		}),
	)

	require.NoError(t, httpServer.Start())

	defer func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}()

	undeliverableHandler := mocks.NewUndeliverableHandler()
	activityStore := memstore.New("service1")
	pubSub := mocks.NewPubSub()

	cfg := &Config{
		ServiceName:    "service1",
		Topic:          "activities",
		PublishTimeout: 100 * time.Millisecond,
		RedeliveryConfig: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.5,
			MaxMessages:    20,
		},
	}

	ob, err := New(cfg, activityStore, pubSub, undeliverableHandler)
	require.NoError(t, err)
	require.NotNil(t, ob)

	ob.Start()

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	toURL, err := url.Parse("http://localhost:8002/services/service1")
	require.NoError(t, err)

	activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName),
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(
					vocab.WithIRI(objIRI),
				),
			),
		),
		vocab.WithTo(toURL),
	)

	require.NoError(t, ob.Post(activity))

	time.Sleep(250 * time.Millisecond)

	mutex.RLock()
	_, ok := activitiesReceived[activity.ID()]
	mutex.RUnlock()
	require.True(t, ok)

	time.Sleep(100 * time.Millisecond)

	ob.Stop()
}

func TestOutbox_PostError(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	activityStore := memstore.New("service1")

	cfg := &Config{
		ServiceName:    "service1",
		Topic:          "activities",
		PublishTimeout: 100 * time.Millisecond,
		RedeliveryConfig: &redelivery.Config{
			MaxRetries:     1,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.5,
			MaxMessages:    20,
		},
	}

	objIRI, err := url.Parse("http://example.com/transactions/txn1")
	require.NoError(t, err)

	toURL, err := url.Parse("http://localhost:8002/services/service1")
	require.NoError(t, err)

	t.Run("Not started", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), mocks.NewUndeliverableHandler())
		require.NoError(t, err)
		require.NotNil(t, ob)

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName), nil)

		require.True(t, errors.Is(ob.Post(activity), spi.ErrNotStarted))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		activityStore := &mocks.ActivityStore{}
		activityStore.AddActivityReturns(errExpected)

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), mocks.NewUndeliverableHandler())
		require.NoError(t, err)
		require.NotNil(t, ob)

		ob.Start()

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceName), nil)

		require.True(t, errors.Is(ob.Post(activity), errExpected))

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Marshal error", func(t *testing.T) {
		ob, err := New(cfg, activityStore, mocks.NewPubSub(), mocks.NewUndeliverableHandler())
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

		ob, err := New(cfg, activityStore, mocks.NewPubSub(), undeliverableHandler)
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
			vocab.WithTo(toURL),
		)

		require.NoError(t, ob.Post(activity))

		time.Sleep(1000 * time.Millisecond)

		undeliverableActivity := undeliverableHandler.Activity(activity.ID())
		require.NotNil(t, undeliverableActivity)

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})

	t.Run("Redelivery unmarshal error", func(t *testing.T) {
		undeliverableHandler := mocks.NewUndeliverableHandler()
		pubSub := mocks.NewPubSub()

		ob, err := New(cfg, activityStore, pubSub, undeliverableHandler)
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
			vocab.WithTo(toURL),
		)

		require.NoError(t, ob.Post(activity))

		time.Sleep(100 * time.Millisecond)

		ob.Stop()
	})
}

func newActivityID(serviceName string) string {
	return fmt.Sprintf("%s/%s", serviceName, uuid.New())
}

type testHandler struct {
	path    string
	handler common.HTTPRequestHandler
}

func newTestHandler(path string, handler common.HTTPRequestHandler) *testHandler {
	return &testHandler{
		path:    path,
		handler: handler,
	}
}

func (m *testHandler) Path() string {
	return m.path
}

func (m *testHandler) Method() string {
	return http.MethodPost
}

func (m *testHandler) Handler() common.HTTPRequestHandler {
	return m.handler
}
