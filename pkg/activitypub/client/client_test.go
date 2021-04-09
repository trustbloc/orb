/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/httptransport.gen.go --fake-name HTTPTransport . httpTransport

func TestClient_GetActor(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/service1")

	actorBytes, err := json.Marshal(aptestutil.NewMockService(actorIRI))
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err = rw.Write(actorBytes)
		require.NoError(t, err)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.NoError(t, e)
		require.NotNil(t, actor)
		require.Equal(t, actorIRI.String(), actor.ID().String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Error status code", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		rw.Code = http.StatusInternalServerError

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Nil(t, actor)
		require.Contains(t, e.Error(), "status code 500")

		require.NoError(t, result.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal client error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err = rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, err := c.GetActor(actorIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Nil(t, actor)

		require.NoError(t, result.Body.Close())
	})
}

func TestClient_GetReferences(t *testing.T) {
	log.SetLevel("activitypub_client", log.DEBUG)

	serviceIRI := testutil.MustParseURL("https://example.com/services/service1")
	collIRI := testutil.NewMockID(serviceIRI, "/followers")

	first := testutil.NewMockID(collIRI, "?page=true")

	followers := []*url.URL{
		testutil.MustParseURL("https://example2.com/services/service2"),
		testutil.MustParseURL("https://example3.com/services/service3"),
		testutil.MustParseURL("https://example4.com/services/service4"),
	}

	collBytes, err := json.Marshal(aptestutil.NewMockCollection(collIRI, first, len(followers)))
	require.NoError(t, err)

	t.Run("Service -> Success", func(t *testing.T) {
		serviceBytes, e := json.Marshal(aptestutil.NewMockService(serviceIRI))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, e = rw.Write(serviceBytes)
		require.NoError(t, e)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(serviceIRI)
		require.NoError(t, e)
		require.NotNil(t, it)

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, 1)
		require.Equal(t, serviceIRI.String(), refs[0].String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Collection -> Success", func(t *testing.T) {
		collPage1Bytes, e := json.Marshal(aptestutil.NewMockCollectionPage(
			testutil.NewMockID(collIRI, "?page=0"),
			testutil.NewMockID(collIRI, "?page=1"),
			collIRI, len(followers),
			followers[0], followers[1],
		))
		require.NoError(t, e)

		collPage2Bytes, e := json.Marshal(aptestutil.NewMockCollectionPage(
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			collIRI, len(followers),
			followers[2],
		))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, e = rw1.Write(collBytes)
		require.NoError(t, e)

		rw2 := httptest.NewRecorder()

		_, e = rw2.Write(collPage1Bytes)
		require.NoError(t, e)

		rw3 := httptest.NewRecorder()

		_, e = rw3.Write(collPage2Bytes)
		require.NoError(t, e)

		result1 := rw1.Result()
		result2 := rw2.Result()
		result3 := rw3.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)
		httpClient.GetReturnsOnCall(2, result3, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.NoError(t, e)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, len(followers))
		require.Equal(t, followers[0].String(), refs[0].String())
		require.Equal(t, followers[1].String(), refs[1].String())
		require.Equal(t, followers[2].String(), refs[2].String())

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
		require.NoError(t, result3.Body.Close())
	})

	t.Run("OrderedCollection -> Success", func(t *testing.T) {
		orderedCollBytes, e := json.Marshal(aptestutil.NewMockOrderedCollection(collIRI, first, len(followers)))
		require.NoError(t, e)

		collPage1Bytes, e := json.Marshal(aptestutil.NewMockOrderedCollectionPage(
			testutil.NewMockID(collIRI, "?page=0"),
			testutil.NewMockID(collIRI, "?page=1"),
			collIRI, len(followers),
			followers[0], followers[1],
		))
		require.NoError(t, e)

		collPage2Bytes, e := json.Marshal(aptestutil.NewMockOrderedCollectionPage(
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			collIRI, len(followers),
			followers[2],
		))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, e = rw1.Write(orderedCollBytes)
		require.NoError(t, e)

		rw2 := httptest.NewRecorder()

		_, e = rw2.Write(collPage1Bytes)
		require.NoError(t, e)

		rw3 := httptest.NewRecorder()

		_, e = rw3.Write(collPage2Bytes)
		require.NoError(t, e)

		result1 := rw1.Result()
		result2 := rw2.Result()
		result3 := rw3.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)
		httpClient.GetReturnsOnCall(2, result3, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.NoError(t, e)
		require.NotNil(t, it)

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, len(followers))
		require.Equal(t, followers[0].String(), refs[0].String())
		require.Equal(t, followers[1].String(), refs[1].String())
		require.Equal(t, followers[2].String(), refs[2].String())

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
		require.NoError(t, result3.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal collection error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err = rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), "unexpected end of JSON input")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid collection error", func(t *testing.T) {
		invalidCollBytes, e := json.Marshal(vocab.NewObject())
		require.NoError(t, e)

		rw := httptest.NewRecorder()

		_, e = rw.Write(invalidCollBytes)
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), "expecting Service, Collection or OrderedCollection in response payload")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Unmarshal collection page error", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, err = rw1.Write(collBytes)
		require.NoError(t, err)

		rw2 := httptest.NewRecorder()

		_, err = rw2.Write([]byte("{"))
		require.NoError(t, err)

		result1 := rw1.Result()
		result2 := rw2.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, err := c.GetReferences(collIRI)
		require.NoError(t, err)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, err := ReadReferences(it, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Empty(t, refs)

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
	})

	t.Run("Invalid collection page error", func(t *testing.T) {
		actorIRI := testutil.MustParseURL("https://example.com/services/service1")

		invalidCollBytes, err := json.Marshal(aptestutil.NewMockService(actorIRI))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, err = rw1.Write(collBytes)
		require.NoError(t, err)

		rw2 := httptest.NewRecorder()

		_, err = rw2.Write(invalidCollBytes)
		require.NoError(t, err)

		result1 := rw1.Result()
		result2 := rw2.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		it, err := c.GetReferences(collIRI)
		require.NoError(t, err)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, err := ReadReferences(it, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting CollectionPage or OrderedCollectionPage in response payload")
		require.Nil(t, refs)

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
	})
}
