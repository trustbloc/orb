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
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const outboxURL = "https://example.com/services/orb/outbox"

func TestNewOutbox(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewOutbox(cfg, memstore.New(""))
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/outbox", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/outbox", id.String())
}

func TestNewInbox(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewInbox(cfg, memstore.New(""))
	require.NotNil(t, h)
	require.Equal(t, "/services/orb/inbox", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	objectIRI, err := h.getObjectIRI(nil)
	require.NoError(t, err)
	require.NotNil(t, objectIRI)
	require.Equal(t, "https://example1.com/services/orb", objectIRI.String())

	id, err := h.getID(objectIRI)
	require.NoError(t, err)
	require.NotNil(t, id)
	require.Equal(t, "https://example1.com/services/orb/inbox", id.String())
}

func TestActivities_Handler(t *testing.T) {
	activityStore := memstore.New("")

	for _, activity := range newMockCreateActivities(19) {
		require.NoError(t, activityStore.AddActivity(activity))
		require.NoError(t, activityStore.AddReference(spi.Outbox, serviceIRI, activity.ID().URL()))
	}

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	t.Run("Success", func(t *testing.T) {
		h := NewOutbox(cfg, activityStore)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, outboxJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected store error")

		s := &mocks.ActivityStore{}
		s.QueryReferencesReturns(nil, errExpected)

		h := NewOutbox(cfg, s)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewOutbox(cfg, activityStore)
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("GetObjectIRI error", func(t *testing.T) {
		h := NewOutbox(cfg, activityStore)
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
		h := NewOutbox(cfg, activityStore)
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
}

func TestActivities_PageHandler(t *testing.T) {
	activityStore := memstore.New("")

	for _, activity := range newMockCreateActivities(19) {
		require.NoError(t, activityStore.AddActivity(activity))
		require.NoError(t, activityStore.AddReference(spi.Outbox, serviceIRI, activity.ID().URL()))
	}

	t.Run("First page -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "true", "", outboxFirstPageJSON)
	})

	t.Run("Page by num -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "true", "3", outboxPage3JSON)
	})

	t.Run("Page num too large -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "true", "30", outboxPageTooLargeJSON)
	})

	t.Run("Last page -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "true", "0", outboxLastPageJSON)
	})

	t.Run("Invalid page-num -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "true", "invalid", outboxFirstPageJSON)
	})

	t.Run("Invalid page -> Success", func(t *testing.T) {
		handleActivitiesRequest(t, serviceIRI, activityStore, "invalid", "3", outboxJSON)
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected store error")

		s := &mocks.ActivityStore{}
		s.QueryActivitiesReturns(nil, errExpected)

		cfg := &Config{
			ObjectIRI: serviceIRI,
			PageSize:  4,
		}

		h := NewOutbox(cfg, s)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "0")
		defer restorePaging()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

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

		h := NewOutbox(cfg, activityStore)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "0")
		defer restorePaging()

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func handleActivitiesRequest(t *testing.T, serviceIRI *url.URL, as spi.Store, page, pageNum, expected string) {
	cfg := &Config{
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewOutbox(cfg, as)
	require.NotNil(t, h)

	restorePaging := setPaging(h.handler, page, pageNum)
	defer restorePaging()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

	h.handle(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)

	respBytes, err := ioutil.ReadAll(result.Body)
	require.NoError(t, err)
	require.NoError(t, result.Body.Close())

	t.Logf("%s", respBytes)

	require.Equal(t, testutil.GetCanonical(t, expected), testutil.GetCanonical(t, string(respBytes)))
}

const (
	outboxJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/outbox",
  "type": "OrderedCollection",
  "totalItems": 19,
  "first": "https://example1.com/services/orb/outbox?page=true",
  "last": "https://example1.com/services/orb/outbox?page=true&page-num=0"
}`

	outboxFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/outbox?page=true&page-num=4",
  "next": "https://example1.com/services/orb/outbox?page=true&page-num=3",
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_18",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_18",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_17",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_17",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_16",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_16",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_15",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_15",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    }
  ],
  "totalItems": 19,
  "type": "OrderedCollectionPage"
}`

	outboxLastPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/outbox?page=true&page-num=0",
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_2",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_2",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_1",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_1",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_0",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_0",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    }
  ],
  "prev": "https://example1.com/services/orb/outbox?page=true&page-num=1",
  "totalItems": 19,
  "type": "OrderedCollectionPage"
}`

	outboxPage3JSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/outbox?page=true&page-num=3",
  "next": "https://example1.com/services/orb/outbox?page=true&page-num=2",
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_14",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_14",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_13",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_13",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_12",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_12",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://activity_11",
      "object": {
        "@context": [
          "https://www.w3.org/ns/activitystreams",
          "https://trustbloc.github.io/Context/orb-v1.json"
        ],
        "id": "https://obj_11",
        "target": {
          "id": "https://example.com/cas/bafkd34G7hD6gbj94fnKm5D",
          "cid": "bafkd34G7hD6gbj94fnKm5D",
          "type": "ContentAddressedStorage"
        },
        "type": "AnchorCredentialReference"
      },
      "type": "Create"
    }
  ],
  "prev": "https://example1.com/services/orb/outbox?page=true&page-num=4",
  "totalItems": 19,
  "type": "OrderedCollectionPage"
}`
	outboxPageTooLargeJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/outbox?page=true&page-num=30",
  "next": "https://example1.com/services/orb/outbox?page=true&page-num=4",
  "totalItems": 19,
  "type": "OrderedCollectionPage"
}`
)
