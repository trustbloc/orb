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
	webDIDEndpoint    = "/.well-known/did.json"
)

func TestGetRESTHandlers(t *testing.T) {
	t.Run("Error - invalid base URL", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{BaseURL: "://"})
		require.EqualError(t, err, "parse base URL: parse \"://\": missing protocol scheme")
		require.Nil(t, c)
	})

	t.Run("Error - empty WebCAS path", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{BaseURL: "https://example.com"})
		require.EqualError(t, err, "webCAS path cannot be empty")
		require.Nil(t, c)
	})

	t.Run("Success", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{BaseURL: "https://example.com", WebCASPath: "/cas"})
		require.NoError(t, err)
		require.Equal(t, 3, len(c.GetRESTHandlers()))
	})
}

func TestWebFinger(t *testing.T) {
	t.Run("test resource query string not exists", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:  "/op",
			ResolutionPath: "/resolve",
			WebCASPath:     "/cas",
			BaseURL:        "http://base",
		})

		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource query string not found")
	})

	t.Run("test resource not found", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:  "/op",
			ResolutionPath: "/resolve",
			WebCASPath:     "/cas",
			BaseURL:        "http://base",
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=wrong", nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource wrong not found")
	})

	t.Run("test resolution resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

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
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=http://base/op", nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, w.Links[0].Href, "http://base/op")
		require.Equal(t, w.Links[1].Href, "http://domain1/op")
		require.Empty(t, w.Properties)
	})

	t.Run("test ipns webfinger document", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			BaseURL:                   "http://base",
			WebCASPath:                "/cas",
			DiscoveryDomains:          []string{"http://domain1"},
			VctURL:                    "http://vct",
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+"?resource=http://base", nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, "http://base", w.Subject)
		require.Equal(t, "http://base/resolve", w.Links[0].Href)
		require.Equal(t, "http://domain1/resolve", w.Links[1].Href)
		require.Equal(t, "http://base/services/orb", w.Properties["https://trustbloc.dev/ns/witness"].(string))
		require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])
		require.Equal(t, "http://base/cas", w.Properties["https://trustbloc.dev/ns/cas"].(string))
		require.Equal(t, "http://base/vct", w.Properties["https://trustbloc.dev/ns/vct"].(string))
		require.Equal(t, "http://base/anchor", w.Properties["https://trustbloc.dev/ns/anchor"].(string))
		require.Equal(t, "http://base/origin", w.Properties["https://trustbloc.dev/ns/origin"].(string))
	})

	t.Run("test WebCAS resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+
			"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
			nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Len(t, w.Links, 3)
		require.Equal(t, w.Links[0].Href,
			"http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y")
		require.Equal(t, w.Links[1].Href,
			"http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y")
		require.Equal(t, w.Links[2].Href,
			"http://domain1/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y")
		require.Empty(t, w.Properties)
	})

	t.Run("test services resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+
			"?resource=http://base/services/orb",
			nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Len(t, w.Links, 1)
		require.Equal(t, w.Links[0].Href,
			"http://base/services/orb")
		require.Empty(t, w.Properties)
	})

	t.Run("test anchor resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+
			"?resource=http://base/anchor",
			nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Len(t, w.Links, 1)
		require.Equal(t, "http://base/anchor", w.Links[0].Href)
		require.Empty(t, w.Properties)
	})

	t.Run("test origin resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, webFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, webFingerEndpoint+
			"?resource=http://base/origin",
			nil, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.WebFingerResponse

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Len(t, w.Links, 1)
		require.Equal(t, "http://base/origin", w.Links[0].Href)
		require.Empty(t, w.Properties)
	})
}

func TestWellKnownDID(t *testing.T) {
	c, err := restapi.New(&restapi.Config{
		BaseURL:    "https://example.com",
		WebCASPath: "/cas",
	})
	require.NoError(t, err)

	handler := getHandler(t, c, webDIDEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, webDIDEndpoint, nil, nil)

	var w restapi.RawDoc

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.ID, "did:web:example.com")
	require.Len(t, w.VerificationMethod, 1)
}

func TestWellKnown(t *testing.T) {
	c, err := restapi.New(&restapi.Config{
		OperationPath:  "/op",
		ResolutionPath: "/resolve",
		WebCASPath:     "/cas",
		BaseURL:        "http://base",
	})
	require.NoError(t, err)

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
	t.Helper()

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
	t.Helper()

	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	t.Helper()

	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	t.Helper()

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
