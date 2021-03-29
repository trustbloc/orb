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

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const basePath = "/services/orb"

var serviceIRI = testutil.MustParseURL("https://example1.com/services/orb")

func TestNewServices(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewServices(cfg, memstore.New(""))
	require.NotNil(t, h)
	require.Equal(t, basePath, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
}

func TestServices_Handler(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	activityStore := memstore.New("")

	require.NoError(t, activityStore.PutActor(newMockService()))

	t.Run("Success", func(t *testing.T) {
		h := NewServices(cfg, activityStore)
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

	t.Run("Store error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected store error")

		s := &mocks.ActivityStore{}
		s.GetActorReturns(nil, errExpected)

		h := NewServices(cfg, s)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewServices(cfg, activityStore)
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
}

func newMockService() *vocab.ActorType {
	const (
		keyID      = "https://example1.com/services/orb#main-key"
		keyOwnerID = "https://example1.com/services/orb"
		keyPem     = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
	)

	followers := testutil.MustParseURL("https://example1.com/services/orb/followers")
	following := testutil.MustParseURL("https://example1.com/services/orb/following")
	inbox := testutil.MustParseURL("https://example1.com.com/services/orb/inbox")
	outbox := testutil.MustParseURL("https://example1.com.com/services/orb/outbox")
	witnesses := testutil.MustParseURL("https://example1.com.com/services/orb/witnesses")
	witnessing := testutil.MustParseURL("https://example1.com.com/services/orb/witnessing")
	liked := testutil.MustParseURL("https://example1.com.com/services/orb/liked")

	publicKey := &vocab.PublicKeyType{
		ID:           keyID,
		Owner:        keyOwnerID,
		PublicKeyPem: keyPem,
	}

	return vocab.NewService(serviceIRI,
		vocab.WithPublicKey(publicKey),
		vocab.WithInbox(inbox),
		vocab.WithOutbox(outbox),
		vocab.WithFollowers(followers),
		vocab.WithFollowing(following),
		vocab.WithWitnesses(witnesses),
		vocab.WithWitnessing(witnessing),
		vocab.WithLiked(liked),
	)
}

const serviceJSON = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
  ],
  "id": "https://example1.com/services/orb",
  "type": "Service",
  "publicKey": {
    "id": "https://example1.com/services/orb#main-key",
    "owner": "https://example1.com/services/orb",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "inbox": "https://example1.com.com/services/orb/inbox",
  "outbox": "https://example1.com.com/services/orb/outbox",
  "followers": "https://example1.com/services/orb/followers",
  "following": "https://example1.com/services/orb/following",
  "liked": "https://example1.com.com/services/orb/liked",
  "witnesses": "https://example1.com.com/services/orb/witnesses",
  "witnessing": "https://example1.com.com/services/orb/witnessing"
}`
