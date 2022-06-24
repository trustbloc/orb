/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginsrest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/mocks"
)

//go:generate counterfeiter -o ../mocks/allowedoriginsmgr.gen.go --fake-name AllowedOriginsMgr . allowedOriginsMgr

const (
	allowedOriginsURL = "https://example.com/allowedorigins"
)

func TestNew(t *testing.T) {
	h := NewWriter(&mocks.AllowedOriginsMgr{})
	require.NotNil(t, h.Handler())
	require.Equal(t, http.MethodPost, h.Method())
	require.Equal(t, "/allowedorigins", h.Path())
}

func TestWriter_Handler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		const (
			domain1 = "https://domain1.com/services/orb"
			domain2 = "https://domain1.com/services/orb"
			domain3 = "https://domain3.com/services/orb"
		)

		request := allowedOriginsRequest{
			Add:    []string{domain1, domain2},
			Remove: []string{domain3},
		}

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		h := NewWriter(&mocks.AllowedOriginsMgr{})
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, allowedOriginsURL, bytes.NewBuffer(requestBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Read request error", func(t *testing.T) {
		errExpected := errors.New("injected read error")

		h := NewWriter(&mocks.AllowedOriginsMgr{})
		require.NotNil(t, h.Handler())

		h.readAll = func(r io.Reader) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, allowedOriginsURL, bytes.NewBuffer([]byte(`[]`)))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Allowed origins manager error", func(t *testing.T) {
		errExpected := errors.New("injected manager error")

		mgr := &mocks.AllowedOriginsMgr{}
		mgr.UpdateReturns(errExpected)

		h := NewWriter(mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, allowedOriginsURL,
			bytes.NewBuffer([]byte(`{"add":["https://domain1.com/services/orb"]}`)))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Bad request", func(t *testing.T) {
		testPostBadRequest(t, "Unmarshal request error", "invalid")
		testPostBadRequest(t, "Invalid add URI", `{"add":[":invalid"]}`)
		testPostBadRequest(t, "Invalid remove URI", `{"remove":[":invalid"]}`)
	})
}

func TestNewReader(t *testing.T) {
	h := NewReader(&mocks.AllowedOriginsMgr{})
	require.NotNil(t, h.Handler())
	require.Equal(t, http.MethodGet, h.Method())
	require.Equal(t, "/allowedorigins", h.Path())
}

func TestReader_Handler(t *testing.T) {
	var (
		domain1 = vocab.MustParseURL("https://domain1.com/services/orb")
		domain2 = vocab.MustParseURL("https://domain1.com/services/orb")
	)

	t.Run("Get all -> success", func(t *testing.T) {
		mgr := &mocks.AllowedOriginsMgr{}

		expected := []*url.URL{domain1, domain2}

		mgr.GetReturns(expected, nil)

		h := NewReader(mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, allowedOriginsURL, nil)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		allowedOrigins := &vocab.URLCollectionProperty{}
		require.NoError(t, json.Unmarshal(respBytes, &allowedOrigins))
		require.Len(t, allowedOrigins.URLs(), 2)
	})

	t.Run("Manager.Get error", func(t *testing.T) {
		errExpected := errors.New("injected manager error")

		mgr := &mocks.AllowedOriginsMgr{}
		mgr.GetReturns(nil, errExpected)

		h := NewReader(mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, allowedOriginsURL, nil)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal allowed origins error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		domain1 := vocab.MustParseURL("https://domain1.com/services/orb")

		mgr := &mocks.AllowedOriginsMgr{}
		mgr.GetReturns([]*url.URL{domain1}, nil)

		h := NewReader(mgr)
		require.NotNil(t, h.Handler())

		h.marshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, allowedOriginsURL, nil)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func testPostBadRequest(t *testing.T, desc, request string) {
	t.Helper()

	t.Run(desc, func(t *testing.T) {
		h := NewWriter(&mocks.AllowedOriginsMgr{})
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, allowedOriginsURL, bytes.NewBuffer([]byte(request)))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
