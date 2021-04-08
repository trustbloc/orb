/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

const (
	wellKnownEndpoint = "/.well-known/did-orb"
	webFingerEndpoint = "/.well-known/webfinger"
)

func TestGetRESTHandlers(t *testing.T) {
	c := restapi.New(&restapi.Config{})
	require.Equal(t, 2, len(c.GetRESTHandlers()))
}

func TestWebFinger(t *testing.T) {
	t.Run("test resource query string not exists", func(t *testing.T) {
		c := restapi.New(&restapi.Config{
			OperationPath:  "/op",
			ResolutionPath: "/resolve",
			BaseURL:        "http://base",
		},
		)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource query string not found")
	})

	t.Run("test resource not found", func(t *testing.T) {
		c := restapi.New(&restapi.Config{
			OperationPath:  "/op",
			ResolutionPath: "/resolve",
			BaseURL:        "http://base",
		},
		)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=wrong", nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource wrong not found")
	})

	t.Run("test resource not found", func(t *testing.T) {
		c := restapi.New(&restapi.Config{
			OperationPath:  "/op",
			ResolutionPath: "/resolve",
			BaseURL:        "http://base",
		},
		)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=wrong", nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource wrong not found")
	})

	t.Run("test resolution resource", func(t *testing.T) {
		c := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		},
		)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=http://base/resolve", nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, w.Links[0].Href, "http://base/resolve")
		require.Equal(t, w.Links[1].Href, "http://domain1/resolve")
		require.Equal(t, w.Properties["https://trustbloc.dev/ns/min-resolvers"], float64(2))
	})

	t.Run("test operation resource", func(t *testing.T) {
		c := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		},
		)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=http://base/op", nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, w.Links[0].Href, "http://base/op")
		require.Equal(t, w.Links[1].Href, "http://domain1/op")
		require.Empty(t, w.Properties)
	})
}

func TestWellKnown(t *testing.T) {
	c := restapi.New(&restapi.Config{
		OperationPath:  "/op",
		ResolutionPath: "/resolve",
		BaseURL:        "http://base",
	},
	)

	handler := getHandler(t, c, wellKnownEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, wellKnownEndpoint, nil, nil)

	var w restapi.WellKnownResponse

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.OperationEndpoint, "http://base/op")
	require.Equal(t, w.ResolutionEndpoint, "http://base/resolve")
}

//nolint:unparam
func serveHTTP(t *testing.T, handler common.HTTPRequestHandler, method, path string,
	req []byte, urlVars map[string]string) *httptest.ResponseRecorder {
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req1 := mux.SetURLVars(httpReq, urlVars)

	handler(rr, req1)

	return rr
}

func getHandler(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
