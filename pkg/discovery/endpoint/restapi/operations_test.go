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
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
)

const (
	didOrbEndpoint   = "/.well-known/did-orb"
	webDIDEndpoint   = "/.well-known/did.json"
	hostMetaEndpoint = "/.well-known/host-meta"
)

type mockResourceInfoProvider struct{}

func (m *mockResourceInfoProvider) GetResourceInfo(string) (registry.Metadata, error) {
	return map[string]interface{}{
		registry.AnchorOriginProperty: "MockAnchorOrigin",
		registry.AnchorURIProperty:    "MockAnchorURI",
	}, nil
}

func (m *mockResourceInfoProvider) Accept(string) bool {
	return true
}

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
		require.Equal(t, 5, len(c.GetRESTHandlers()))
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

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint, nil, nil, false)

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

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=wrong", nil, nil, false)

		require.Equal(t, http.StatusNotFound, rr.Code)
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

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=http://base/resolve",
			nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, "http://base/resolve", w.Links[0].Href)
		require.Equal(t, "http://domain1/resolve", w.Links[1].Href)
		require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])
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

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=http://base/op",
			nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Equal(t, "http://base/op", w.Links[0].Href)
		require.Equal(t, "http://domain1/op", w.Links[1].Href)
		require.Empty(t, w.Properties)
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

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
			"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
		require.Len(t, w.Links, 3)
		require.Equal(t, "http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
			w.Links[0].Href)
		require.Equal(t, "http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
			w.Links[1].Href)
		require.Equal(t, "http://domain1/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
			w.Links[2].Href)
		require.Empty(t, w.Properties)
	})

	t.Run("test did:orb resource", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			BaseURL:                   "http://base",
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryVctDomains:       []string{"http://vct.com/maple2019"},
			DiscoveryMinimumResolvers: 2,
			VctURL:                    "http://vct.com/maple2020",
			ResourceRegistry:          registry.New(registry.WithResourceInfoProvider(&mockResourceInfoProvider{})),
		})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
			"?resource=did:orb:suffix", nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

		require.Len(t, w.Properties, 2)

		require.Equal(t, "MockAnchorOrigin", w.Properties["https://trustbloc.dev/ns/anchor-origin"])
		require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])

		require.Len(t, w.Links, 4)

		require.Equal(t, "self", w.Links[0].Rel)
		require.Equal(t, "application/did+ld+json", w.Links[0].Type)
		require.Equal(t, "http://base/sidetree/v1/identifiers/did:orb:suffix", w.Links[0].Href)

		require.Equal(t, "via", w.Links[1].Rel)
		require.Equal(t, "application/ld+json", w.Links[1].Type)
		require.Equal(t, "MockAnchorURI", w.Links[1].Href)

		require.Equal(t, "service", w.Links[2].Rel)
		require.Equal(t, "application/activity+json", w.Links[2].Type)
		require.Equal(t, "http://base/services/orb", w.Links[2].Href)

		require.Equal(t, "alternate", w.Links[3].Rel)
		require.Equal(t, "application/did+ld+json", w.Links[3].Type)
		require.Equal(t, "http://domain1/sidetree/v1/identifiers/did:orb:suffix", w.Links[3].Href)
	})
}

func TestHostMeta(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("via /.well.known/host-meta endpoint", func(t *testing.T) {
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

			handler := getHandler(t, c, hostMetaEndpoint)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, hostMetaEndpoint, nil, nil,
				true)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
			require.Len(t, w.Links, 4)
			require.Equal(t, "self", w.Links[0].Rel)
			require.Equal(t, "application/jrd+json", w.Links[0].Type)
			require.Equal(t, "http://base/.well-known/webfinger?resource={uri}", w.Links[0].Template)

			require.Equal(t, "self", w.Links[1].Rel)
			require.Equal(t, restapi.ActivityJSONType, w.Links[1].Type)
			require.Equal(t, "http://base/services/orb", w.Links[1].Href)

			require.Equal(t, "alternate", w.Links[2].Rel)
			require.Equal(t, "application/jrd+json", w.Links[2].Type)
			require.Equal(t, "http://domain1/.well-known/webfinger?resource={uri}", w.Links[2].Template)

			require.Equal(t, "alternate", w.Links[3].Rel)
			require.Equal(t, restapi.ActivityJSONType, w.Links[3].Type)
			require.Equal(t, "http://domain1/services/orb", w.Links[3].Href)
		})
		t.Run("via /.well.known/host-meta.json endpoint", func(t *testing.T) {
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

			handler := getHandler(t, c, restapi.HostMetaJSONEndpoint)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.HostMetaJSONEndpoint, nil, nil,
				true)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
			require.Len(t, w.Links, 4)
			require.Equal(t, "self", w.Links[0].Rel)
			require.Equal(t, "application/jrd+json", w.Links[0].Type)
			require.Equal(t, "http://base/.well-known/webfinger?resource={uri}", w.Links[0].Template)

			require.Equal(t, "self", w.Links[1].Rel)
			require.Equal(t, restapi.ActivityJSONType, w.Links[1].Type)
			require.Equal(t, "http://base/services/orb", w.Links[1].Href)

			require.Equal(t, "alternate", w.Links[2].Rel)
			require.Equal(t, "application/jrd+json", w.Links[2].Type)
			require.Equal(t, "http://domain1/.well-known/webfinger?resource={uri}", w.Links[2].Template)

			require.Equal(t, "alternate", w.Links[3].Rel)
			require.Equal(t, restapi.ActivityJSONType, w.Links[3].Type)
			require.Equal(t, "http://domain1/services/orb", w.Links[3].Href)
		})
	})
	t.Run("Accept header missing", func(t *testing.T) {
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

		handler := getHandler(t, c, hostMetaEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, hostMetaEndpoint, nil, nil,
			false)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response restapi.ErrorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, "the Accept header must be set to application/json to use this endpoint",
			response.Message)
	})
}

func TestWellKnownDID(t *testing.T) {
	c, err := restapi.New(&restapi.Config{
		BaseURL:    "https://example.com",
		WebCASPath: "/cas",
	})
	require.NoError(t, err)

	handler := getHandler(t, c, webDIDEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, webDIDEndpoint, nil, nil, false)

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

	handler := getHandler(t, c, didOrbEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, didOrbEndpoint, nil, nil, false)

	var w restapi.WellKnownResponse

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.OperationEndpoint, "http://base/op")
	require.Equal(t, w.ResolutionEndpoint, "http://base/resolve")
}

//nolint:unparam
func serveHTTP(t *testing.T, handler common.HTTPRequestHandler, method, path string,
	req []byte, urlVars map[string]string, includeAcceptHeader bool) *httptest.ResponseRecorder {
	t.Helper()

	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	if includeAcceptHeader {
		httpReq.Header.Add("Accept", "application/json")
	}

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
