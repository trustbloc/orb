/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	aperrors "github.com/trustbloc/orb/pkg/activitypub/errors"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/inbox/httpsubscriber"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/activityhandler.gen.go --fake-name ActivityHandler ../spi ActivityHandler
//go:generate counterfeiter -o ../mocks/activitystore.gen.go --fake-name ActivityStore ../../store/spi Store
//go:generate counterfeiter -o ../mocks/sigfnatureverifier.gen.go --fake-name SignatureVerifier . signatureVerifier

func TestInbox_StartStop(t *testing.T) {
	cfg := &Config{
		ServiceEndpoint: "/services/service1/inbox",
		ServiceIRI:      testutil.MustParseURL("https://example1.com/services/service1"),
		Topic:           "activities",
	}

	ib, err := New(cfg, memstore.New(cfg.ServiceEndpoint), mocks.NewPubSub(), &mocks.ActivityHandler{},
		&mocks.SignatureVerifier{})
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

	service1InboxURL := service1URL + resthandler.InboxPath

	cfg := &Config{
		ServiceEndpoint: "/services/service1/inbox",
		ServiceIRI:      testutil.MustParseURL(service1URL),
		Topic:           "activities",
	}

	objIRI, err := url.Parse("http://example.com//services/service1/object1")
	if err != nil {
		panic(err)
	}

	activityHandler := &mocks.ActivityHandler{}
	activityStore := memstore.New(cfg.ServiceEndpoint)

	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

	ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler, sigVerifier)
	require.NoError(t, err)
	require.NotNil(t, ib)

	ib.Start()

	stop := startHTTPServer(t, ":8202", ib.HTTPHandler())
	defer stop()

	time.Sleep(500 * time.Millisecond)

	client := http.Client{}

	t.Run("Success", func(t *testing.T) {
		activityHandler.HandleActivityReturns(nil)

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		// Wait for the activity to be handled
		time.Sleep(50 * time.Millisecond)

		a, err := activityStore.GetActivity(activity.ID().URL())
		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equalf(t, activity.ID(), a.ID(), "The activity should have been stored in the inbox")

		it, err := activityStore.QueryReferences(store.Inbox,
			store.NewCriteria(
				store.WithObjectIRI(cfg.ServiceIRI),
				store.WithReferenceIRI(activity.ID().URL()),
			),
		)
		require.NoError(t, err)
		require.NotNil(t, it)
		require.Equal(t, 1, it.TotalItems())
	})

	ib.Stop()

	time.Sleep(50 * time.Millisecond)

	require.Equal(t, spi.StateStopped, ib.State())
}

//nolint:gocyclo,cyclop
func TestInbox_Error(t *testing.T) {
	log.SetLevel("activitypub_service", log.DEBUG)

	client := http.Client{}

	t.Run("Handler error", func(t *testing.T) {
		const service1URL = "http://localhost:8204/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, store.ErrNotFound)

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8204", ib.HTTPHandler())
		defer stop()

		time.Sleep(100 * time.Millisecond)

		activityHandler.HandleActivityReturns(fmt.Errorf("injected handler error"))

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("Store error", func(t *testing.T) {
		const service1URL = "http://localhost:8205/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI := testutil.MustParseURL("http://example.com//services/service1/object1")

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, store.ErrNotFound)

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8205", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activityStore.AddActivityReturns(fmt.Errorf("injected store error"))

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		const service1URL = "http://localhost:8206/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, store.ErrNotFound)

		pubSub := mocks.NewPubSub()
		undeliverableChan, err := pubSub.Subscribe(context.Background(), spi.UndeliverableTopic)
		require.NoError(t, err)

		var undeliverableMessages []*message.Message

		done := make(chan struct{})
		go func() {
			for msg := range undeliverableChan {
				undeliverableMessages = append(undeliverableMessages, msg)
				close(done)
			}
		}()

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, pubSub, activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		errExpected := fmt.Errorf("injected unmarshal error")

		ib.jsonUnmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8206", ib.HTTPHandler())
		defer stop()

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		select {
		case <-done:
		case <-time.After(time.Second):
		}

		require.Empty(t, undeliverableMessages)
	})

	t.Run("PubSub subscribe error", func(t *testing.T) {
		const service1URL = "http://localhost:8205/services/service1"

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, store.ErrNotFound)

		errExpected := fmt.Errorf("injected pub sub error")

		ib, err := New(cfg, activityStore, mocks.NewPubSub().WithError(errExpected), activityHandler,
			&mocks.SignatureVerifier{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, ib)
	})

	t.Run("Duplicate activity error", func(t *testing.T) {
		const service1URL = "http://localhost:8207/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI, err := url.Parse("http://example.com//services/service1/object1")
		if err != nil {
			panic(err)
		}

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, mocks.NewPubSub(), activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8207", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("GetActivity error", func(t *testing.T) {
		const service1URL = "http://localhost:8208/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI := testutil.MustParseURL("http://example.com//services/service1/object1")

		pubSub := mocks.NewPubSub()
		undeliverableChan, err := pubSub.Subscribe(context.Background(), spi.UndeliverableTopic)
		require.NoError(t, err)

		var undeliverableMessages []*message.Message

		done := make(chan struct{})
		go func() {
			for msg := range undeliverableChan {
				undeliverableMessages = append(undeliverableMessages, msg)
				close(done)
			}
		}()

		errExpected := fmt.Errorf("injected store error")

		activityHandler := &mocks.ActivityHandler{}
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, errExpected)

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, pubSub, activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8208", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout")
		}

		require.Len(t, undeliverableMessages, 1)
	})

	t.Run("Transient error", func(t *testing.T) {
		const service1URL = "http://localhost:8208/services/service1"

		service1InboxURL := service1URL + resthandler.InboxPath

		cfg := &Config{
			ServiceEndpoint: "/services/service1/inbox",
			ServiceIRI:      testutil.MustParseURL(service1URL),
			Topic:           "activities",
		}

		objIRI := testutil.MustParseURL("http://example.com//services/service1/object1")

		pubSub := mocks.NewPubSub()
		undeliverableChan, err := pubSub.Subscribe(context.Background(), spi.UndeliverableTopic)
		require.NoError(t, err)

		var undeliverableMessages []*message.Message

		done := make(chan struct{})
		go func() {
			for msg := range undeliverableChan {
				undeliverableMessages = append(undeliverableMessages, msg)
				close(done)
			}
		}()

		errExpected := aperrors.NewTransient(errors.New("injected transient error"))

		activityHandler := &mocks.ActivityHandler{}
		activityHandler.HandleActivityReturns(errExpected)
		activityStore := &mocks.ActivityStore{}
		activityStore.GetActivityReturns(nil, store.ErrNotFound)

		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, cfg.ServiceIRI, nil)

		ib, err := New(cfg, activityStore, pubSub, activityHandler, sigVerifier)
		require.NoError(t, err)
		require.NotNil(t, ib)

		ib.Start()
		defer ib.Stop()

		stop := startHTTPServer(t, ":8208", ib.HTTPHandler())
		defer stop()

		time.Sleep(500 * time.Millisecond)

		activity := vocab.NewCreateActivity(
			vocab.NewObjectProperty(
				vocab.WithObject(
					vocab.NewObject(
						vocab.WithIRI(objIRI),
					),
				),
			),
			vocab.WithID(newActivityID(cfg.ServiceEndpoint)),
			vocab.WithActor(cfg.ServiceIRI),
		)

		req, err := newHTTPRequest(service1InboxURL, activity)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout")
		}

		require.Len(t, undeliverableMessages, 1)
	})
}

func TestUnmarshalAndValidateActivity(t *testing.T) {
	activityID := testutil.MustParseURL("https://example1.com/activities/activity1")
	actorIRI := testutil.MustParseURL("https://example1.com/services/service1")

	ib, e := New(&Config{VerifyActorInSignature: true}, memstore.New(""), mocks.NewPubSub(),
		nil, nil)
	require.NoError(t, e)
	require.NotNil(t, ib)

	t.Run("Success", func(t *testing.T) {
		activity := vocab.NewCreateActivity(nil, vocab.WithID(activityID), vocab.WithActor(actorIRI))

		activityBytes, err := json.Marshal(activity)
		require.NoError(t, err)

		msg := message.NewMessage("msg1", activityBytes)
		msg.Metadata[httpsubscriber.ActorIRIKey] = actorIRI.String()

		a, err := ib.unmarshalAndValidateActivity(msg)
		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equal(t, activity.ID().String(), a.ID().String())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		a, err := ib.unmarshalAndValidateActivity(message.NewMessage("msg1", []byte("{")))
		require.EqualError(t, err, "unmarshal activity: unexpected end of JSON input")
		require.Nil(t, a)
	})

	t.Run("No actor IRI in message error", func(t *testing.T) {
		activity := vocab.NewCreateActivity(nil,
			vocab.WithID(activityID),
			vocab.WithActor(actorIRI),
		)

		activityBytes, err := json.Marshal(activity)
		require.NoError(t, err)

		a, err := ib.unmarshalAndValidateActivity(message.NewMessage("msg1", activityBytes))
		require.EqualError(t, err, "no actorIRI specified in message context")
		require.Nil(t, a)
	})

	t.Run("Nil actor in activity error", func(t *testing.T) {
		activity := vocab.NewCreateActivity(nil, vocab.WithID(activityID))

		activityBytes, err := json.Marshal(activity)
		require.NoError(t, err)

		msg := message.NewMessage("msg1", activityBytes)
		msg.Metadata[httpsubscriber.ActorIRIKey] = "https://example1.com/services/service1"

		a, err := ib.unmarshalAndValidateActivity(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no actor specified in activity")
		require.Nil(t, a)
	})

	t.Run("Actor mismatch error", func(t *testing.T) {
		actorIRI := testutil.MustParseURL("https://example1.com/services/service1")
		activity := vocab.NewCreateActivity(nil, vocab.WithID(activityID), vocab.WithActor(actorIRI))

		activityBytes, err := json.Marshal(activity)
		require.NoError(t, err)

		msg := message.NewMessage("msg1", activityBytes)
		msg.Metadata[httpsubscriber.ActorIRIKey] = "https://example1.com/services/service2"

		a, err := ib.unmarshalAndValidateActivity(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match the actor in the HTTP signature")
		require.Nil(t, a)
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
		return nil, fmt.Errorf("marshal metadata to JSON: %w", err)
	}

	req.Header.Set(wmhttp.HeaderMetadata, string(metadataBytes))

	return req, nil
}

func newActivityID(serviceName string) *url.URL {
	return testutil.MustParseURL(fmt.Sprintf("%s/%s", serviceName, uuid.New()))
}

func startHTTPServer(t *testing.T, listenAddress string, handlers ...common.HTTPHandler) func() {
	t.Helper()

	httpServer := httpserver.New(listenAddress, "", "", handlers...)

	require.NoError(t, httpServer.Start())

	return func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}
}
