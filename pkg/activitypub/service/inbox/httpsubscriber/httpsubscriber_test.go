/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsubscriber

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	endpoint   = "/services/service1"
	serviceURL = "http://localhost:8202/services/service1"
)

func TestNew(t *testing.T) {
	s := New(&Config{ServiceEndpoint: endpoint}, &mocks.SignatureVerifier{})
	require.NotNil(t, s)

	require.Equal(t, spi.StateStarted, s.State())
	require.Equal(t, http.MethodPost, s.Method())
	require.Equal(t, endpoint, s.Path())
	require.NotNil(t, endpoint, s.Handler())

	require.NoError(t, s.Close())

	require.Equal(t, spi.StateStopped, s.State())
}

func TestSubscriber_HandleAck(t *testing.T) {
	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	msgChan, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, msgChan)

	go func() {
		for msg := range msgChan {
			msg.Ack()
		}
	}()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, endpoint, nil)

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)
	require.NoError(t, result.Body.Close())
}

func TestSubscriber_HandleNack(t *testing.T) {
	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	msgChan, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, msgChan)

	go func() {
		for msg := range msgChan {
			msg.Nack()
		}
	}()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, endpoint, nil)

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusInternalServerError, result.StatusCode)
	require.NoError(t, result.Body.Close())
}

func TestSubscriber_HandleRequestTimeout(t *testing.T) {
	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	_, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)

	rw := httptest.NewRecorder()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	require.NotNil(t, ctx)
	require.NotNil(t, cancel)

	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("data")))
	require.NoError(t, err)
	require.NotNil(t, req)

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusInternalServerError, result.StatusCode)
	require.NoError(t, result.Body.Close())
}

func TestSubscriber_UnmarshalError(t *testing.T) {
	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	msgChan, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, msgChan)

	rw := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(nil))
	require.NoError(t, err)

	req.Header.Add(wmhttp.HeaderMetadata, "{invalid")

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.NoError(t, result.Body.Close())
}

func TestSubscriber_Close(t *testing.T) {
	t.Run("Publish when stopped", func(t *testing.T) {
		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

		s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
		require.NotNil(t, s)

		_, err := s.Subscribe(context.Background(), "")
		require.NoError(t, err)

		var mutex sync.Mutex
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)

		go func() {
			time.Sleep(50 * time.Millisecond)

			mutex.Lock()
			s.handleMessage(rw, req)
			mutex.Unlock()
		}()

		s.stop()

		mutex.Lock()
		result := rw.Result()
		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)
		require.NoError(t, result.Body.Close())
		mutex.Unlock()
	})

	t.Run("Respond when stopped", func(t *testing.T) {
		sigVerifier := &mocks.SignatureVerifier{}
		sigVerifier.VerifyRequestReturns(true, testutil.MustParseURL(serviceURL), nil)

		s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
		require.NotNil(t, s)

		_, err := s.Subscribe(context.Background(), "")
		require.NoError(t, err)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, endpoint, nil)

		go func() {
			time.Sleep(10 * time.Millisecond)
			s.stop()
		}()

		s.handleMessage(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func TestSubscriber_InvalidHTTPSignature(t *testing.T) {
	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(false, nil, nil)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	msgChan, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, msgChan)

	go func() {
		for msg := range msgChan {
			msg.Ack()
		}
	}()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, endpoint, nil)

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusUnauthorized, result.StatusCode)
	require.NoError(t, result.Body.Close())
}

func TestSubscriber_HTTPSignatureError(t *testing.T) {
	errExpected := fmt.Errorf("injected verifier error")

	sigVerifier := &mocks.SignatureVerifier{}
	sigVerifier.VerifyRequestReturns(false, nil, errExpected)

	s := New(&Config{ServiceEndpoint: endpoint}, sigVerifier)
	require.NotNil(t, s)

	defer s.Stop()

	msgChan, err := s.Subscribe(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, msgChan)

	go func() {
		for msg := range msgChan {
			msg.Ack()
		}
	}()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, endpoint, nil)

	s.handleMessage(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusInternalServerError, result.StatusCode)
	require.NoError(t, result.Body.Close())
}
