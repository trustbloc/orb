/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcresthandler

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
)

const (
	namespace = "verifiable"
	id        = "id"
	content   = "{}"
)

func TestNew(t *testing.T) {
	store, err := mem.NewProvider().OpenStore(namespace)
	require.NoError(t, err)

	handler := New(store)
	require.NotNil(t, handler)
	require.Equal(t, fmt.Sprintf("/vc/{%s}", idPathVariable), handler.Path())
	require.Equal(t, http.MethodGet, handler.Method())
	require.NotNil(t, handler.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := mem.NewProvider().OpenStore(namespace)
		require.NoError(t, err)

		err = store.Put(id, []byte(content))
		require.NoError(t, err)

		handler := New(store)
		require.NotNil(t, handler)

		router := mux.NewRouter()

		router.HandleFunc(handler.Path(), handler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/vc/" + id)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NotEmpty(t, responseBody)
	})

	t.Run("error - not found", func(t *testing.T) {
		store, err := mem.NewProvider().OpenStore(namespace)
		require.NoError(t, err)

		handler := New(store)
		require.NotNil(t, handler)

		router := mux.NewRouter()

		router.HandleFunc(handler.Path(), handler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/vc/abc")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusNotFound, response.StatusCode)
		require.Equal(t, statusNotFoundResponse, string(responseBody))
	})

	t.Run("error - anchor event store error", func(t *testing.T) {
		store := &mockstore.Store{ErrGet: fmt.Errorf("store get error")}

		handler := New(store)
		require.NotNil(t, handler)

		router := mux.NewRouter()

		router.HandleFunc(handler.Path(), handler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/vc/abc")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)
		require.Equal(t, internalServerErrorResponse, string(responseBody))
	})
}
