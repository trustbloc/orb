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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	transactionsBaseBath = "/transactions"
	objectID             = "d607506e-6964-4991-a19f-674952380760"
	outboxURL            = "https://example.com/services/orb/outbox"
	sharesURL            = "https://example.com/services/orb/followers"
)

var transactionsIRI = testutil.MustParseURL("https://sally.example.com/transactions")

func TestNewOutbox(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := NewOutbox(cfg, memstore.New(""), &mocks.SignatureVerifier{})
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

	h := NewInbox(cfg, memstore.New(""), &mocks.SignatureVerifier{})
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

func TestNewShares(t *testing.T) {
	cfg := &Config{
		BasePath:  transactionsBaseBath,
		ObjectIRI: transactionsIRI,
	}

	h := NewShares(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/transactions/{id}/shares", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	t.Run("Success", func(t *testing.T) {
		restore := setIDParam(objectID)
		defer restore()

		objectIRI, err := h.getObjectIRI(nil)
		require.NoError(t, err)
		require.NotNil(t, objectIRI)
		require.Equal(t, "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760", objectIRI.String())

		id, err := h.getID(objectIRI)
		require.NoError(t, err)
		require.NotNil(t, id)
		require.Equal(t, "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares", id.String())
	})

	t.Run("No ID in URL -> error", func(t *testing.T) {
		restore := setIDParam("")
		defer restore()

		objectIRI, err := h.getObjectIRI(nil)
		require.EqualError(t, err, "id not specified in URL")
		require.Nil(t, objectIRI)
	})
}

func TestNewLikes(t *testing.T) {
	cfg := &Config{
		BasePath:  transactionsBaseBath,
		ObjectIRI: transactionsIRI,
	}

	h := NewLikes(cfg, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, "/transactions/{id}/likes", h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())

	t.Run("Success", func(t *testing.T) {
		restore := setIDParam(objectID)
		defer restore()

		objectIRI, err := h.getObjectIRI(nil)
		require.NoError(t, err)
		require.NotNil(t, objectIRI)
		require.Equal(t, "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760", objectIRI.String())

		id, err := h.getID(objectIRI)
		require.NoError(t, err)
		require.NotNil(t, id)
		require.Equal(t, "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/likes", id.String())
	})

	t.Run("No ID in URL -> error", func(t *testing.T) {
		restore := setIDParam("")
		defer restore()

		objectIRI, err := h.getObjectIRI(nil)
		require.EqualError(t, err, "id not specified in URL")
		require.Nil(t, objectIRI)
	})
}

func TestActivities_Handler(t *testing.T) {
	activityStore := memstore.New("")

	for _, activity := range newMockCreateActivities(19) {
		require.NoError(t, activityStore.AddActivity(activity))
		require.NoError(t, activityStore.AddReference(spi.Outbox, serviceIRI, activity.ID().URL()))
	}

	require.NoError(t, activityStore.AddReference(spi.Follower, serviceIRI, service2IRI))

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
		AuthTokensDef: []*AuthTokenDef{
			{
				EndpointExpression: "/services/orb/outbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
			{
				EndpointExpression: "/services/orb/inbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
		},
		AuthTokens: map[string]string{
			"read":  "READ_TOKEN",
			"admin": "ADMIN_TOKEN",
		},
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, service2IRI, nil)

	t.Run("Success", func(t *testing.T) {
		h := NewOutbox(cfg, activityStore, verifier)
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

		h := NewOutbox(cfg, s, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewOutbox(cfg, activityStore, verifier)
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
		h := NewOutbox(cfg, activityStore, verifier)
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
		h := NewOutbox(cfg, activityStore, verifier)
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

		h := NewOutbox(cfg, activityStore, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid signature", func(t *testing.T) {
		verifier := &mocks.SignatureVerifier{}
		verifier.VerifyRequestReturns(false, nil, nil)

		h := NewOutbox(cfg, activityStore, verifier)
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, outboxURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func TestActivities_PageHandler(t *testing.T) {
	activityStore := memstore.New("")

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

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

		h := NewOutbox(cfg, s, verifier)
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

		h := NewOutbox(cfg, activityStore, verifier)
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

func TestShares_Handler(t *testing.T) {
	objectIRI := testutil.NewMockID(transactionsIRI, "/"+objectID)

	shares := newMockActivities(vocab.TypeAnnounce, 19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/activities/announce_activity_%d", i, i)
	})

	activityStore := memstore.New("")

	for _, a := range shares {
		require.NoError(t, activityStore.AddActivity(a))
		require.NoError(t, activityStore.AddReference(spi.Share, objectIRI, a.ID().URL()))
	}

	cfg := &Config{
		BasePath:  transactionsBaseBath,
		ObjectIRI: transactionsIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	t.Run("Success", func(t *testing.T) {
		h := NewShares(cfg, activityStore, verifier)
		require.NotNil(t, h)

		restore := setIDParam(objectID)
		defer restore()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, sharesURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, sharesJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})
}

func TestShares_PageHandler(t *testing.T) {
	const objectID = "d607506e-6964-4991-a19f-674952380760"

	objectIRI := testutil.NewMockID(transactionsIRI, "/"+objectID)

	shares := newMockActivities(vocab.TypeAnnounce, 19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/activities/announce_activity_%d", i, i)
	})

	activityStore := memstore.New("")

	for _, a := range shares {
		require.NoError(t, activityStore.AddActivity(a))
		require.NoError(t, activityStore.AddReference(spi.Share, objectIRI, a.ID().URL()))
	}

	cfg := &Config{
		BasePath:  transactionsBaseBath,
		ObjectIRI: transactionsIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	t.Run("First page -> Success", func(t *testing.T) {
		h := NewShares(cfg, activityStore, verifier)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "")
		defer restorePaging()

		restore := setIDParam(objectID)
		defer restore()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, sharesURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, sharesFirstPageJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("By page -> Success", func(t *testing.T) {
		h := NewShares(cfg, activityStore, verifier)
		require.NotNil(t, h)

		restorePaging := setPaging(h.handler, "true", "1")
		defer restorePaging()

		restore := setIDParam(objectID)
		defer restore()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, sharesURL, nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, sharesPage1JSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})
}

func TestLiked_Handler(t *testing.T) {
	liked := newMockActivities(vocab.TypeLike, 19, func(i int) string {
		return fmt.Sprintf("https://example%d.com/activities/like_activity_%d", i, i)
	})

	activityStore := memstore.New("")

	for _, a := range liked {
		require.NoError(t, activityStore.AddActivity(a))
		require.NoError(t, activityStore.AddReference(spi.Liked, serviceIRI, a.ID().URL()))
	}

	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  2,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	h := NewLiked(cfg, activityStore, verifier)
	require.NotNil(t, h)

	t.Run("Main page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "false", "", likedJSON)
	})

	t.Run("First page -> Success", func(t *testing.T) {
		handleRequest(t, h.handler, h.handle, "true", "", likedFirstPageJSON)
	})
}

func TestNewActivity(t *testing.T) {
	h := NewActivity(&Config{BasePath: basePath}, memstore.New(""), &mocks.SignatureVerifier{})
	require.NotNil(t, h)
	require.Equal(t, basePath+ActivitiesPath, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
}

func TestActivity_Handler(t *testing.T) {
	id := "abd35f29-032f-4e22-8f52-df00365323bc"

	activityID := testutil.NewMockID(serviceIRI, fmt.Sprintf("/activities/%s", id))
	activity := newMockActivity(vocab.TypeCreate, activityID)

	cfg := &Config{
		ObjectIRI: serviceIRI,
		BasePath:  basePath,
	}

	activityStore := memstore.New("")
	require.NoError(t, activityStore.AddActivity(activity))

	t.Run("Success", func(t *testing.T) {
		h := NewActivity(cfg, activityStore, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(id)
		defer restoreID()

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, testutil.GetCanonical(t, activityJSON), testutil.GetCanonical(t, string(respBytes)))
		require.NoError(t, result.Body.Close())
	})

	t.Run("No activity ID -> BadRequest", func(t *testing.T) {
		h := NewActivity(cfg, activityStore, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusBadRequest, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Activity ID not found -> NotFound", func(t *testing.T) {
		h := NewActivity(cfg, activityStore, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam("123")
		defer restoreID()

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusNotFound, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Store error", func(t *testing.T) {
		as := &mocks.ActivityStore{}
		as.GetActivityReturns(nil, errors.New("injected store error"))

		h := NewActivity(cfg, as, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(id)
		defer restoreID()

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Marshal error", func(t *testing.T) {
		h := NewActivity(cfg, activityStore, &mocks.SignatureVerifier{})
		require.NotNil(t, h)

		errExpected := fmt.Errorf("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, serviceIRI.String(), nil)

		restoreID := setIDParam(id)
		defer restoreID()

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

func handleActivitiesRequest(t *testing.T, serviceIRI *url.URL, as spi.Store, page, pageNum, expected string) {
	t.Helper()

	cfg := &Config{
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	verifier := &mocks.SignatureVerifier{}
	verifier.VerifyRequestReturns(true, serviceIRI, nil)

	h := NewOutbox(cfg, as, verifier)
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

func newMockActivities(t vocab.Type, num int, getURI func(i int) string) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		activities[i] = newMockActivity(t, testutil.MustParseURL(getURI(i)))
	}

	return activities
}

func newMockActivity(t vocab.Type, id *url.URL) *vocab.ActivityType {
	if t == vocab.TypeAnnounce {
		return vocab.NewAnnounceActivity(vocab.NewObjectProperty(vocab.WithIRI(id)), vocab.WithID(id))
	}

	if t == vocab.TypeLike {
		result, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(jsonLikeResult)))
		if err != nil {
			panic(err)
		}

		actor := testutil.MustParseURL("https://example1.com/services/orb")
		credID := testutil.MustParseURL("http://sally.example.com/transactions/bafkreihwsn")

		startTime := getStaticTime()
		endTime := startTime.Add(1 * time.Minute)

		return vocab.NewLikeActivity(
			vocab.NewObjectProperty(vocab.WithIRI(credID)),
			vocab.WithID(id),
			vocab.WithActor(actor),
			vocab.WithStartTime(&startTime),
			vocab.WithEndTime(&endTime),
			vocab.WithResult(vocab.NewObjectProperty(vocab.WithObject(result))),
		)
	}

	return vocab.NewCreateActivity(vocab.NewObjectProperty(
		vocab.WithIRI(testutil.MustParseURL("http://sally.example.com/transactions/bafkreihwsn"))),
		vocab.WithID(id))
}

func getStaticTime() time.Time {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		panic(err)
	}

	return time.Date(2021, time.January, 27, 9, 30, 10, 0, loc)
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
          "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
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
	sharesJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "first": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true",
  "id": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares",
  "last": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=0",
  "totalItems": 19,
  "type": "OrderedCollection"
}`

	sharesFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=4",
  "type": "OrderedCollectionPage",
  "next": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=3",
  "totalItems": 19,
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example18.com/activities/announce_activity_18",
      "object": "https://example18.com/activities/announce_activity_18",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example17.com/activities/announce_activity_17",
      "object": "https://example17.com/activities/announce_activity_17",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example16.com/activities/announce_activity_16",
      "object": "https://example16.com/activities/announce_activity_16",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example15.com/activities/announce_activity_15",
      "object": "https://example15.com/activities/announce_activity_15",
      "type": "Announce"
    }
  ]
}`

	sharesPage1JSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=1",
  "type": "OrderedCollectionPage",
  "next": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=0",
  "prev": "https://sally.example.com/transactions/d607506e-6964-4991-a19f-674952380760/shares?page=true&page-num=2",
  "totalItems": 19,
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example6.com/activities/announce_activity_6",
      "object": "https://example6.com/activities/announce_activity_6",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example5.com/activities/announce_activity_5",
      "object": "https://example5.com/activities/announce_activity_5",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example4.com/activities/announce_activity_4",
      "object": "https://example4.com/activities/announce_activity_4",
      "type": "Announce"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "id": "https://example3.com/activities/announce_activity_3",
      "object": "https://example3.com/activities/announce_activity_3",
      "type": "Announce"
    }
  ]
}`

	likedJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/liked",
  "type": "OrderedCollection",
  "totalItems": 19,
  "first": "https://example1.com/services/orb/liked?page=true",
  "last": "https://example1.com/services/orb/liked?page=true&page-num=0"
}`

	likedFirstPageJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/liked?page=true&page-num=9",
  "next": "https://example1.com/services/orb/liked?page=true&page-num=8",
  "orderedItems": [
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "actor": "https://example1.com/services/orb",
      "endTime": "2021-01-27T09:31:10Z",
      "id": "https://example18.com/activities/like_activity_18",
      "object": "http://sally.example.com/transactions/bafkreihwsn",
      "result": {
        "@context": [
          "https://w3id.org/security/v1",
          "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
        ],
        "proof": {
          "created": "2021-01-27T09:30:15Z",
          "domain": "https://witness1.example.com/ledgers/maple2021",
          "jws": "eyJ...",
          "proofPurpose": "assertionMethod",
          "type": "JsonWebSignature2020",
          "verificationMethod": "did:example:abcd#key"
        }
      },
      "startTime": "2021-01-27T09:30:10Z",
      "type": "Like"
    },
    {
      "@context": "https://www.w3.org/ns/activitystreams",
      "actor": "https://example1.com/services/orb",
      "endTime": "2021-01-27T09:31:10Z",
      "id": "https://example17.com/activities/like_activity_17",
      "object": "http://sally.example.com/transactions/bafkreihwsn",
      "result": {
        "@context": [
          "https://w3id.org/security/v1",
          "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
        ],
        "proof": {
          "created": "2021-01-27T09:30:15Z",
          "domain": "https://witness1.example.com/ledgers/maple2021",
          "jws": "eyJ...",
          "proofPurpose": "assertionMethod",
          "type": "JsonWebSignature2020",
          "verificationMethod": "did:example:abcd#key"
        }
      },
      "startTime": "2021-01-27T09:30:10Z",
      "type": "Like"
    }
  ],
  "totalItems": 19,
  "type": "OrderedCollectionPage"
}`

	jsonLikeResult = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
  "proof": {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:15Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "https://witness1.example.com/ledgers/maple2021",
    "jws": "eyJ..."
  }
}`

	activityJSON = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://example1.com/services/orb/activities/abd35f29-032f-4e22-8f52-df00365323bc",
  "object": "http://sally.example.com/transactions/bafkreihwsn",
  "type": "Create"
}`
)
