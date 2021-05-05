/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNewOutboxAdmin(t *testing.T) {
	cfg := &Config{
		BasePath:  "/services/orb",
		ObjectIRI: serviceIRI,
	}

	ob := &mocks.Outbox{}
	verifier := &mocks.SignatureVerifier{}

	h := NewPostOutbox(cfg, ob, verifier)

	require.NotNil(t, h.Handler())
	require.Equal(t, http.MethodPost, h.Method())
	require.Equal(t, "/services/orb/outbox", h.Path())
}

func TestOutbox_Handler(t *testing.T) {
	const outboxURL = "https://example1.com/services/orb/outbox"

	service2IRI := testutil.MustParseURL("https://example2.com/services/orb")

	cfg := &Config{
		BasePath:               "/services/orb",
		ObjectIRI:              serviceIRI,
		VerifyActorInSignature: true,
	}

	ob := &mocks.Outbox{}

	activity := vocab.NewFollowActivity(
		vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
		vocab.WithActor(serviceIRI),
		vocab.WithTo(service2IRI),
	)

	activityBytes, err := json.Marshal(activity)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, serviceIRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(activityBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid HTTP signature", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, serviceIRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(activityBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("HTTP signature verifier error", func(t *testing.T) {
		errExpected := errors.New("injected signature verifier error")

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, errExpected)

		h := NewPostOutbox(cfg, ob, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(activityBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("No activity in request -> error", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, serviceIRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, nil)

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Outbox Post error", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, serviceIRI, nil)

		errExpected := errors.New("injected outbox error")

		outb := &mocks.Outbox{}
		outb.WithError(errExpected)

		h := NewPostOutbox(cfg, outb, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(activityBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid actor IRI", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, service2IRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(activityBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Nil actor in activity", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, serviceIRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		a := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithTo(service2IRI),
		)

		aBytes, err := json.Marshal(a)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(aBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid actor in activity", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(true, serviceIRI, nil)

		h := NewPostOutbox(cfg, ob, verifier)

		a := vocab.NewFollowActivity(
			vocab.NewObjectProperty(vocab.WithIRI(service2IRI)),
			vocab.WithActor(service2IRI),
			vocab.WithTo(service2IRI),
		)

		aBytes, err := json.Marshal(a)
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, outboxURL, bytes.NewBuffer(aBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
