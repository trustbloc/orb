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

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testSuffix = "suffix"
	testCID    = "cid"
)

func TestNew(t *testing.T) {
	store, err := didanchorstore.New(mem.NewProvider())
	require.NoError(t, err)

	didAnchorHandler := New(store)
	require.NotNil(t, didAnchorHandler)
	require.Equal(t, endpoint, didAnchorHandler.Path())
	require.Equal(t, http.MethodGet, didAnchorHandler.Method())
	require.NotNil(t, didAnchorHandler.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)

		didAnchorHandler := New(store)
		require.NotNil(t, didAnchorHandler)

		router := mux.NewRouter()

		router.HandleFunc(didAnchorHandler.Path(), didAnchorHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/anchor/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusOK, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, testCID, string(respBytes))
	})

	t.Run("error - anchor not found for suffix", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		didAnchorHandler := New(store)
		require.NotNil(t, didAnchorHandler)

		router := mux.NewRouter()

		router.HandleFunc(didAnchorHandler.Path(), didAnchorHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/anchor/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusNotFound, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, notFoundResponse, string(respBytes))
	})

	t.Run("error - store error", func(t *testing.T) {
		mockStore := &storemocks.Store{}
		mockStore.GetReturns(nil, fmt.Errorf("get error"))

		mockProvider := &storemocks.Provider{}
		mockProvider.OpenStoreReturns(mockStore, nil)

		store, err := didanchorstore.New(mockProvider)
		require.NoError(t, err)

		didAnchorHandler := New(store)
		require.NotNil(t, didAnchorHandler)

		router := mux.NewRouter()

		router.HandleFunc(didAnchorHandler.Path(), didAnchorHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/anchor/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})
}
