/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
)

//go:generate counterfeiter -o ../mocks/activityhandler.gen.go --fake-name ActivityHandler ../spi ActivityHandler
//go:generate counterfeiter -o ../mocks/activitystore.gen.go --fake-name ActivityStore ../../store/spi Store

func TestInbox_StartStop(t *testing.T) {
	cfg := &Config{
		ServiceEndpoint: "/services/service1",
		Topic:           "activities",
	}

	ib, err := New(cfg, memstore.New(cfg.ServiceEndpoint), mocks.NewPubSub(), &mocks.ActivityHandler{})
	require.NoError(t, err)
	require.NotNil(t, ib)

	require.Equal(t, spi.StateNotStarted, ib.State())

	ib.Start()

	stop := startHTTPServer(t, ":8201", ib.HTTPHandler())
	defer stop()

	time.Sleep(50 * time.Millisecond)

	require.Equal(t, spi.StateStarted, ib.State())

	ib.Stop()

	require.Equal(t, spi.StateStopped, ib.State())
}

func TestInbox_Handle(t *testing.T) {
	const service1URL = "http://localhost:8202/services/service1"

	cfg := &Config{
		ServiceEndpoint: "/services/service1",
		Topic:           "activities",
	}

	objIRI, err := url.Parse("http://example.com//services/service1/object1")
	if err != nil {
		panic(err)
	}

	activityHandler := &mocks.ActivityHandler{}
	activityStore := memstore.New(cfg.ServiceEndpoint)

	ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler)
	require.NoError(t, err)
	require.NotNil(t, ib)

	ib.Start()

	stop := startHTTPServer(t, ":8202", ib.HTTPHandler())
	defer stop()

	time.Sleep(500 * time.Millisecond)

	client := http.Client{}

	t.Run("Success", func(t *testing.T) {
		activityHandler.HandleActivityReturns(nil)

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceEndpoint),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
		)

		req, err := newHTTPRequest(service1URL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		// Wait for the activity to be handled
		time.Sleep(50 * time.Millisecond)

		a, err := activityStore.GetActivity(store.Inbox, activity.ID().URL())
		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equalf(t, activity.ID(), a.ID(), "The activity should have been stored in the inbox")
	})

	ib.Stop()

	time.Sleep(50 * time.Millisecond)

	require.Equal(t, spi.StateStopped, ib.State())
}

func TestInbox_Error(t *testing.T) {
	client := http.Client{}

	t.Run("Handler error", func(t *testing.T) {
		const service1URL = "http://localhost:8204/services/service1"

		cfg := &Config{
			ServiceEndpoint: "/services/service1",
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8204", ib.HTTPHandler())
		defer stop()

		time.Sleep(100 * time.Millisecond)

		activityHandler.HandleActivityReturns(errors.New("injected handler error"))

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceEndpoint),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
		)

		req, err := newHTTPRequest(service1URL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("Store error", func(t *testing.T) {
		const service1URL = "http://localhost:8205/services/service1"

		cfg := &Config{
			ServiceEndpoint: "/services/service1",
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8205", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activityStore.AddActivityReturns(errors.New("injected store error"))

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceEndpoint),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
		)

		req, err := newHTTPRequest(service1URL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		const service1URL = "http://localhost:8206/services/service1"

		cfg := &Config{
			ServiceEndpoint: "/services/service1",
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler)
		require.NoError(t, err)
		require.NotNil(t, ib)

		errExpected := errors.New("injected unmarshal error")

		ib.jsonUnmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8206", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activityHandler.HandleActivityReturns(errors.New("injected handler error"))

		activity := vocab.NewCreateActivity(newActivityID(cfg.ServiceEndpoint),
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
		)

		req, err := newHTTPRequest(service1URL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("PubSub subscribe error", func(t *testing.T) {
		cfg := &Config{
			ServiceEndpoint: "/services/service1",
			Topic:           "activities",
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}

		errExpected := errors.New("injected pub sub error")

		ib, err := New(cfg, activityStore, mocks.NewPubSub().WithError(errExpected), activityHandler)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, ib)
	})
}

func newHTTPRequest(u string, activity *vocab.ActivityType) (*http.Request, error) {
	activityBytes, err := json.Marshal(activity)
	if err != nil {
		return nil, err
	}

	msg := message.NewMessage(watermill.NewUUID(), activityBytes)

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewBuffer(msg.Payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set(wmhttp.HeaderUUID, msg.UUID)

	metadataBytes, err := json.Marshal(msg.Metadata)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal metadata to JSON")
	}

	req.Header.Set(wmhttp.HeaderMetadata, string(metadataBytes))

	return req, nil
}

func newActivityID(serviceName string) *url.URL {
	return mustParseURL(fmt.Sprintf("%s/%s", serviceName, uuid.New()))
}

func startHTTPServer(t *testing.T, listenAddress string, handlers ...common.HTTPHandler) func() {
	httpServer := httpserver.New(listenAddress, "", "", "", handlers...)

	require.NoError(t, httpServer.Start())

	return func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}
