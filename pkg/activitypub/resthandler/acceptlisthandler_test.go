/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

//go:generate counterfeiter -o ../mocks/acceptlistmgr.gen.go --fake-name AcceptListMgr . acceptListMgr

const (
	acceptListURL = "https://example.com/services/orb/acceptlist"
)

func TestNewAcceptListWriter(t *testing.T) {
	cfg := &Config{
		BasePath: "/services/orb",
	}

	h := NewAcceptListWriter(cfg, &mocks.AcceptListMgr{})
	require.NotNil(t, h.Handler())
	require.Equal(t, http.MethodPost, h.Method())
	require.Equal(t, "/services/orb/acceptlist", h.Path())
}

func TestAcceptListWriter_Handler(t *testing.T) {
	cfg := &Config{
		BasePath: "/services/orb",
	}

	t.Run("Success", func(t *testing.T) {
		const (
			domain1 = "https://domain1.com/services/orb"
			domain2 = "https://domain1.com/services/orb"
			domain3 = "https://domain3.com/services/orb"
		)

		requests := []acceptListRequest{
			{
				Type:   "follow",
				Add:    []string{domain1, domain2},
				Remove: []string{domain3},
			},
			{
				Type: "invite-witness",
				Add:  []string{domain2, domain3},
			},
		}

		requestBytes, err := json.Marshal(requests)
		require.NoError(t, err)

		h := NewAcceptListWriter(cfg, &mocks.AcceptListMgr{})
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, acceptListURL, bytes.NewBuffer(requestBytes))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Read request error", func(t *testing.T) {
		errExpected := errors.New("injected read error")

		h := NewAcceptListWriter(cfg, &mocks.AcceptListMgr{})
		require.NotNil(t, h.Handler())

		h.readAll = func(r io.Reader) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, acceptListURL, bytes.NewBufferString(`[]`))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Accept list manager error", func(t *testing.T) {
		errExpected := errors.New("injected manager error")

		mgr := &mocks.AcceptListMgr{}
		mgr.UpdateReturns(errExpected)

		h := NewAcceptListWriter(cfg, mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, acceptListURL,
			bytes.NewBufferString(`[{"type":"follow","add":["https://domain1.com/services/orb"]}]`))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Bad request", func(t *testing.T) {
		testPostBadRequest(t, "Unmarshal request error", "invalid")
		testPostBadRequest(t, "Type not specified", `[{}]`)
		testPostBadRequest(t, "Invalid add URI", `[{"type":"follow","add":[":invalid"]}]`)
		testPostBadRequest(t, "Invalid remove URI", `[{"type":"follow","remove":[":invalid"]}]`)
	})
}

func TestNewAcceptListReader(t *testing.T) {
	cfg := &Config{
		BasePath: "/services/orb",
	}

	h := NewAcceptListReader(cfg, &mocks.AcceptListMgr{})
	require.NotNil(t, h.Handler())
	require.Equal(t, http.MethodGet, h.Method())
	require.Equal(t, "/services/orb/acceptlist", h.Path())
}

func TestAcceptListReader_Handler(t *testing.T) {
	var (
		domain1 = vocab.MustParseURL("https://domain1.com/services/orb")
		domain2 = vocab.MustParseURL("https://domain1.com/services/orb")
	)

	cfg := &Config{
		BasePath: "/services/orb",
	}

	t.Run("Get by type -> success", func(t *testing.T) {
		mgr := &mocks.AcceptListMgr{}
		mgr.GetReturns([]*url.URL{domain1, domain2}, nil)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		restoreType := setTypeParam("follow")
		defer restoreType()

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		acceptList := &acceptList{}
		require.NoError(t, json.Unmarshal(respBytes, acceptList))
		require.Equal(t, acceptList.Type, "follow")
		require.Len(t, acceptList.URLs, 2)
		require.Equal(t, domain1.String(), acceptList.URLs[0])
		require.Equal(t, domain2.String(), acceptList.URLs[1])
	})

	t.Run("Get all -> success", func(t *testing.T) {
		mgr := &mocks.AcceptListMgr{}

		expected := []*spi.AcceptList{
			{
				Type: "follow",
				URL:  []*url.URL{domain1, domain2},
			},
			{
				Type: "invite-witness",
				URL:  []*url.URL{domain1},
			},
		}

		mgr.GetAllReturns(expected, nil)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		require.NoError(t, result.Body.Close())

		var acceptLists []*acceptList
		require.NoError(t, json.Unmarshal(respBytes, &acceptLists))
		require.Len(t, acceptLists, 2)
	})

	t.Run("Manager.Get error", func(t *testing.T) {
		errExpected := errors.New("injected manager error")

		mgr := &mocks.AcceptListMgr{}
		mgr.GetReturns(nil, errExpected)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		restoreType := setTypeParam("follow")
		defer restoreType()

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Manager.GetAll error", func(t *testing.T) {
		errExpected := errors.New("injected manager error")

		mgr := &mocks.AcceptListMgr{}
		mgr.GetAllReturns(nil, errExpected)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal accept list error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		domain1 := vocab.MustParseURL("https://domain1.com/services/orb")

		mgr := &mocks.AcceptListMgr{}
		mgr.GetReturns([]*url.URL{domain1}, nil)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		h.marshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		restoreType := setTypeParam("follow")
		defer restoreType()

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal accept lists error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		domain1 := vocab.MustParseURL("https://domain1.com/services/orb")

		mgr := &mocks.AcceptListMgr{}

		mgr.GetAllReturns([]*spi.AcceptList{
			{
				Type: "follow",
				URL:  []*url.URL{domain1, domain2},
			},
		}, nil)

		h := NewAcceptListReader(cfg, mgr)
		require.NotNil(t, h.Handler())

		h.marshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, acceptListURL, http.NoBody)

		h.handleGet(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func testPostBadRequest(t *testing.T, desc, request string) {
	t.Helper()

	cfg := &Config{
		BasePath: "/services/orb",
	}

	t.Run(desc, func(t *testing.T) {
		h := NewAcceptListWriter(cfg, &mocks.AcceptListMgr{})
		require.NotNil(t, h.Handler())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, acceptListURL, bytes.NewBufferString(request))

		h.handlePost(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}
