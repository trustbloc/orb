/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const followersURL = "https://example.com/services/orb/followers"

func TestNewFollowers(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewFollowers(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/followers", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/followers", id.String())
}

func TestNewFollowing(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewFollowing(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/following", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/following", id.String())
}

func TestNewWitnesses(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewWitnesses(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/witnesses", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/witnesses", id.String())
}

func TestNewWitnessing(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewWitnessing(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/witnessing", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/witnessing", id.String())
}

func TestFollowers_Handler(t *testing.T) {
	followers := testutil.NewMockURLs(19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/services/orb", i)
	})

	activityStore := memstore.New("")

	for _, ref := range followers {
		require.NoError(t, activityStore.AddReference(spi.Follower, serviceIRI, ref))
	}

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	t.Run("Success", func(t *testing.T) {
		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, followersJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected store error")

		s := &mocks.ActivityStore{}
		s.QueryReferencesReturns(nil, errExpected)

		h := NewFollowers(cfg, s, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("GetObjectIRI error", func(t *testing.T) {
		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected error")

		h.getObjectIRI = func(req *http.Request) (*url.URL, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("GetID error", func(t *testing.T) {
		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected error")

		h.getID = func(*url.URL) (*url.URL, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Verify signature error", func(t *testing.T) {
		errExpected := errors.New("injected verifier error")

		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, errExpected)

		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid signature", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, nil)

		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func TestFollowers_PageHandler(t *testing.T) {
	followers := testutil.NewMockURLs(19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/services/orb", i+1)
	})

	activityStore := memstore.New("")

	for _, ref := range followers {
		require.NoError(t, activityStore.AddReference(spi.Follower, serviceIRI, ref))
	}

	cfg := &Config{
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	h := NewFollowers(cfg, activityStore, verifier)
	require.NotNil(t, h)

	t.Run("First page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "", followersFirstPageJSON)
	})

	t.Run("Page by num -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "3", followersPage3JSON)
	})

	t.Run("Page num too large -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "30", followersPageTooLargeJSON)
	})

	t.Run("Last page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "4", followersLastPageJSON)
	})

	t.Run("Invalid page-num -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "invalid", followersFirstPageJSON)
	})

	t.Run("Invalid page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "invalid", "3", followersJSON)
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected store error")

		s := &mocks.ActivityStore{}
		s.QueryReferencesReturns(nil, errExpected)

		cfg := &Config{
			ObjectIRI: serviceIRI,
			PageSize:  4,
		}

		h := NewFollowers(cfg, s, verifier)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "0")
		defer restorePaging()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		cfg := &Config{
			ObjectIRI: serviceIRI,
			PageSize:  4,
		}

		h := NewFollowers(cfg, activityStore, verifier)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "0")
		defer restorePaging()

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, followersURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func TestWitnesses_Handler(t *testing.T) {
	witnesses := testutil.NewMockURLs(19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/services/orb", i+1)
	})

	activityStore := memstore.New("")

	for _, ref := range witnesses {
		require.NoError(t, activityStore.AddReference(spi.Witness, serviceIRI, ref))
	}

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	h := NewWitnesses(cfg, activityStore, verifier)
	require.NotNil(t, h)

	t.Run("Main page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "false", "", witnessesJSON)
	})

	t.Run("First page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "", witnessesFirstPageJSON)
	})

	t.Run("Page by num -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "3", witnessesPage3JSON)
	})
}

func TestWitnessing_Handler(t *testing.T) {
	witnessing := testutil.NewMockURLs(19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/services/orb", i+1)
	})

	activityStore := memstore.New("")

	for _, ref := range witnessing {
		require.NoError(t, activityStore.AddReference(spi.Witnessing, serviceIRI, ref))
	}

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	h := NewWitnessing(cfg, activityStore, verifier)
	require.NotNil(t, h)

	t.Run("Main page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "false", "", witnessingJSON)
	})

	t.Run("First page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "", witnessingFirstPageJSON)
	})

	t.Run("Page by num -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "3", witnessingPage3JSON)
	})
}

func handleRequest(t *testing.T, h *handler, handle http.HandlerFunc, page, pageNum, expected string) {
	t.Helper()

	restorePaging := setPaging(h, page, pageNum)
	defer restorePaging()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/services/orb", nil)

	handle(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)

	respBytes, err := ioutil.ReadAll(result.Body)
	require.NoError(t, err)
	require.NoError(t, result.Body.Close())

	t.Logf("%s", respBytes)

	require.Equal(t, testutil.GetCanonical(t, expected), testutil.GetCanonical(t, string(respBytes)))
}

const (
	followersJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/followers",
  "type": "Collection",
  "totalItems": 19,
  "first": "https://example1.com/services/orb/followers?page=true",
  "last": "https://example1.com/services/orb/followers?page=true&page-num=4"
}`

	followersFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/followers?page=true&page-num=0",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/followers?page=true&page-num=1",
  "items": [
    "https://example1.com/services/orb",
    "https://example2.com/services/orb",
    "https://example3.com/services/orb",
    "https://example4.com/services/orb"
  ]
}`

	followersLastPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/followers?page=true&page-num=4",
  "type": "CollectionPage",
  "totalItems": 19,
  "prev": "https://example1.com/services/orb/followers?page=true&page-num=3",
  "items": [
    "https://example17.com/services/orb",
    "https://example18.com/services/orb",
    "https://example19.com/services/orb"
  ]
}`

	followersPage3JSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/followers?page=true&page-num=3",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/followers?page=true&page-num=4",
  "prev": "https://example1.com/services/orb/followers?page=true&page-num=2",
  "items": [
    "https://example13.com/services/orb",
    "https://example14.com/services/orb",
    "https://example15.com/services/orb",
    "https://example16.com/services/orb"
  ]
}`

	followersPageTooLargeJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/followers?page=true&page-num=30",
  "type": "CollectionPage",
  "totalItems": 19,
  "prev": "https://example1.com/services/orb/followers?page=true&page-num=4"
}`

	witnessesJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnesses",
  "type": "Collection",
  "totalItems": 19,
  "first": "https://example1.com/services/orb/witnesses?page=true",
  "last": "https://example1.com/services/orb/witnesses?page=true&page-num=4"
}`

	witnessesFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnesses?page=true&page-num=0",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/witnesses?page=true&page-num=1",
  "items": [
    "https://example1.com/services/orb",
    "https://example2.com/services/orb",
    "https://example3.com/services/orb",
    "https://example4.com/services/orb"
  ]
}`

	witnessesPage3JSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnesses?page=true&page-num=3",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/witnesses?page=true&page-num=4",
  "prev": "https://example1.com/services/orb/witnesses?page=true&page-num=2",
  "items": [
    "https://example13.com/services/orb",
    "https://example14.com/services/orb",
    "https://example15.com/services/orb",
    "https://example16.com/services/orb"
  ]
}`

	witnessingJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnessing",
  "type": "Collection",
  "totalItems": 19,
  "first": "https://example1.com/services/orb/witnessing?page=true",
  "last": "https://example1.com/services/orb/witnessing?page=true&page-num=4"
}`

	witnessingFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnessing?page=true&page-num=0",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/witnessing?page=true&page-num=1",
  "items": [
    "https://example1.com/services/orb",
    "https://example2.com/services/orb",
    "https://example3.com/services/orb",
    "https://example4.com/services/orb"
  ]
}`

	witnessingPage3JSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/witnessing?page=true&page-num=3",
  "type": "CollectionPage",
  "totalItems": 19,
  "next": "https://example1.com/services/orb/witnessing?page=true&page-num=4",
  "prev": "https://example1.com/services/orb/witnessing?page=true&page-num=2",
  "items": [
    "https://example13.com/services/orb",
    "https://example14.com/services/orb",
    "https://example15.com/services/orb",
    "https://example16.com/services/orb"
  ]
}`
)
