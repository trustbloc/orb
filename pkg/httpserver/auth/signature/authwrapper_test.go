/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/httpserver/auth/signature/mocks"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//nolint:lll
//go:generate counterfeiter -o ./mocks/httphandler.gen.go --fake-name HTTPHandler github.com/trustbloc/sidetree-core-go/pkg/restapi/common.HTTPHandler

func TestNewAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		testHandler := &mocks.HTTPHandler{}
		testHandler.MethodReturns(http.MethodGet)
		testHandler.PathReturns("/identifiers/{id}")

		authHandler := NewHandlerWrapper(testHandler, &resthandler.Config{}, memstore.New(""), &apmocks.SignatureVerifier{})
		require.NotNil(t, authHandler)
		require.Equal(t, testHandler.Method(), authHandler.Method())
		require.Equal(t, testHandler.Path(), authHandler.Path())
	})
}

func TestAuthHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		testHandler := &mocks.HTTPHandler{}
		testHandler.MethodReturns(http.MethodGet)
		testHandler.PathReturns("/identifiers/{id}")
		testHandler.HandlerReturns(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
		})

		authHandler := NewHandlerWrapper(testHandler, &resthandler.Config{}, memstore.New(""), &apmocks.SignatureVerifier{})
		require.NotNil(t, authHandler)

		router := mux.NewRouter()

		router.HandleFunc(authHandler.Path(), authHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/identifiers/" + "abc")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "{}", string(responseBody))
	})

	t.Run("authorization test cases", func(t *testing.T) {
		cfg := &resthandler.Config{
			Config: auth.Config{
				AuthTokensDef: []*auth.TokenDef{
					{
						EndpointExpression: "/identifiers",
						ReadTokens:         []string{"read"},
					},
				},
				AuthTokens: map[string]string{
					"read": "READ_TOKEN",
				},
			},
		}

		testHandler := &mocks.HTTPHandler{}
		testHandler.MethodReturns(http.MethodGet)
		testHandler.PathReturns("/identifiers/{id}")
		testHandler.HandlerReturns(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		t.Run("success - authorized", func(t *testing.T) {
			actor := testutil.MustParseURL("https://sally.example.com/services/orb")

			v := &apmocks.SignatureVerifier{}
			v.VerifyRequestReturns(true, actor, nil)

			authHandler := NewHandlerWrapper(testHandler, cfg, memstore.New(""), v)
			require.NotNil(t, authHandler)

			router := mux.NewRouter()

			router.HandleFunc(authHandler.Path(), authHandler.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/identifiers/abc")
			require.NoError(t, err)

			require.Equal(t, http.StatusNotFound, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})

		t.Run("error - unauthorized", func(t *testing.T) {
			authHandler := NewHandlerWrapper(testHandler, cfg, memstore.New(""), &apmocks.SignatureVerifier{})
			require.NotNil(t, authHandler)

			router := mux.NewRouter()

			router.HandleFunc(authHandler.Path(), authHandler.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/identifiers/rst")
			require.NoError(t, err)

			require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})

		t.Run("error - authorization error", func(t *testing.T) {
			sigVerifier := &apmocks.SignatureVerifier{}
			sigVerifier.VerifyRequestReturns(false, nil, errors.New("injected authorization error"))

			authHandler := NewHandlerWrapper(testHandler, cfg, memstore.New(""), sigVerifier)
			require.NotNil(t, authHandler)

			router := mux.NewRouter()

			router.HandleFunc(authHandler.Path(), authHandler.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/identifiers/abc")
			require.NoError(t, err)

			require.Equal(t, http.StatusInternalServerError, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})
	})
}
