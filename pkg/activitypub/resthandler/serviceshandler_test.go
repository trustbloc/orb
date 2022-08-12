/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	basePath      = "/services/orb"
	publicKeyPath = "/services/orb/keys/{id}"
	keyPem        = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
)

var (
	serviceIRI   = testutil.MustParseURL("https://example1.com/services/orb")
	service2IRI  = testutil.MustParseURL("https://example2.com/services/orb")
	publicKeyIRI = testutil.NewMockID(serviceIRI, "/keys/main-key")
)

var publicKey = vocab.NewPublicKey(
	vocab.WithID(publicKeyIRI),
	vocab.WithOwner(serviceIRI),
	vocab.WithPublicKeyPem(keyPem),
)

func TestNewServices(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewServices(cfg, memstore.New(""), publicKey, &apmocks.AuthTokenMgr{})
	require.NotNil(t, h)
	require.Equal(t, basePath, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
}

func TestNewPublicKey(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewPublicKeys(cfg, memstore.New(""), publicKey, &apmocks.AuthTokenMgr{})
	require.NotNil(t, h)
	require.Equal(t, publicKeyPath, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
}

func TestServices_Handler(t *testing.T) {
	cfg := &Config{
		BasePath:           basePath,
		ObjectIRI:          serviceIRI,
		ServiceEndpointURL: serviceIRI,
		PageSize:           4,
	}

	activityStore := memstore.New("")

	t.Run("Success", func(t *testing.T) {
		h := NewServices(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, serviceJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewServices(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Unauthorized", func(t *testing.T) {
		cfg := &Config{
			BasePath:  basePath,
			ObjectIRI: serviceIRI,
			PageSize:  4,
		}

		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"read"}, nil)

		h := NewServices(cfg, activityStore, publicKey, tm)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func TestPublicKeys_Handler(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
	}

	activityStore := memstore.New("")

	t.Run("Success", func(t *testing.T) {
		h := NewPublicKeys(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(MainKeyID)
		defer restoreID()

		h.handlePublicKey(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, publicKeyJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("No key ID -> BadRequest", func(t *testing.T) {
		h := NewPublicKeys(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handlePublicKey(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Key ID not found -> NotFound", func(t *testing.T) {
		h := NewPublicKeys(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam("invalid-key")
		defer restoreID()

		h.handlePublicKey(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewPublicKeys(cfg, activityStore, publicKey, &apmocks.AuthTokenMgr{})
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(MainKeyID)
		defer restoreID()

		h.handlePublicKey(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Unauthorized", func(t *testing.T) {
		cfg := &Config{
			BasePath:  basePath,
			ObjectIRI: serviceIRI,
			PageSize:  4,
		}

		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"read"}, nil)

		h := NewPublicKeys(cfg, activityStore, publicKey, tm)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(MainKeyID)
		defer restoreID()

		h.handlePublicKey(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

const (
	serviceJSON = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "followers": "https://example1.com/services/orb/followers",
  "following": "https://example1.com/services/orb/following",
  "id": "https://example1.com/services/orb",
  "inbox": "https://example1.com/services/orb/inbox",
  "liked": "https://example1.com/services/orb/liked",
  "likes": "https://example1.com/services/orb/likes",
  "outbox": "https://example1.com/services/orb/outbox",
  "publicKey": {
    "id": "https://example1.com/services/orb/keys/main-key",
    "owner": "https://example1.com/services/orb",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "shares": "https://example1.com/services/orb/shares",
  "type": "Service",
  "witnesses": "https://example1.com/services/orb/witnesses",
  "witnessing": "https://example1.com/services/orb/witnessing"
}`

	publicKeyJSON = `{
  "id": "https://example1.com/services/orb/keys/main-key",
  "owner": "https://example1.com/services/orb",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
}`
)
