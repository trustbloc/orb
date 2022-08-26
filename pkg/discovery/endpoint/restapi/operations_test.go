/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi_test

//go:generate counterfeiter -o ./mocks/webresolver.gen.go --fake-name WebResolver . webResolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/cas/resolver/mocks"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	endpointmocks "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi/mocks"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	didOrbEndpoint   = "/.well-known/did-orb"
	webDIDEndpoint   = "/.well-known/did.json"
	hostMetaEndpoint = "/.well-known/host-meta"
	nodeInfoEndpoint = "/.well-known/nodeinfo"

	orbWebDIDFileEndpoint     = "/scid/{id}/did.json"
	orbWebDIDResolverEndpoint = "/1.0/identifiers/did:web:base:scid:{id}"

	suffix = "suffix"
)

type mockResourceInfoProvider struct {
	anchorOrigin interface{}
	anchorURI    interface{}
	canonicalRef interface{}
	err          error
}

func newMockResourceInfoProvider() *mockResourceInfoProvider {
	return &mockResourceInfoProvider{
		anchorOrigin: "MockAnchorOrigin",
		anchorURI:    "MockAnchorURI",
	}
}

func (m *mockResourceInfoProvider) withAnchorOrigin(value interface{}) *mockResourceInfoProvider {
	m.anchorOrigin = value

	return m
}

func (m *mockResourceInfoProvider) withAnchorURI(value interface{}) *mockResourceInfoProvider {
	m.anchorURI = value

	return m
}

func (m *mockResourceInfoProvider) withCanonicalRef(value interface{}) *mockResourceInfoProvider {
	m.canonicalRef = value

	return m
}

func (m *mockResourceInfoProvider) withError(err error) *mockResourceInfoProvider {
	m.err = err

	return m
}

func (m *mockResourceInfoProvider) GetResourceInfo(string) (registry.Metadata, error) {
	if m.err != nil {
		return nil, m.err
	}

	metadata := make(map[string]interface{})

	if m.anchorOrigin != nil {
		metadata[registry.AnchorOriginProperty] = m.anchorOrigin
	}

	if m.anchorURI != nil {
		metadata[registry.AnchorURIProperty] = m.anchorURI
	}

	if m.canonicalRef != nil {
		metadata[registry.CanonicalReferenceProperty] = m.canonicalRef
	}

	return metadata, nil
}

func (m *mockResourceInfoProvider) Accept(string) bool {
	return true
}

func TestGetRESTHandlers(t *testing.T) {
	t.Run("Error - empty WebCAS path", func(t *testing.T) {
		c, err := restapi.New(
			&restapi.Config{
				ServiceEndpointURL: testutil.MustParseURL("https://example.com"),
			},
			&restapi.Providers{},
		)
		require.EqualError(t, err, "webCAS path cannot be empty")
		require.Nil(t, c)
	})

	t.Run("HTTP service ID Success", func(t *testing.T) {
		c, err := restapi.New(
			&restapi.Config{
				ServiceEndpointURL: testutil.MustParseURL("https://example.com"),
				WebCASPath:         "/cas",
			},
			&restapi.Providers{},
		)
		require.NoError(t, err)
		require.Equal(t, 8, len(c.GetRESTHandlers()))
	})

	t.Run("HTTP service ID Success", func(t *testing.T) {
		cfg := &restapi.Config{
			ServiceID:          testutil.MustParseURL("did:web:example.com:services:orb"),
			ServiceEndpointURL: testutil.MustParseURL("https://example.com"),
			WebCASPath:         "/cas",
		}

		c, err := restapi.New(cfg, &restapi.Providers{})
		require.NoError(t, err)
		require.Equal(t, 9, len(c.GetRESTHandlers()),
			"Expecting 9 handlers, including the service did handler")
	})
}

func TestWebFinger(t *testing.T) {
	t.Run("test resource query string not exists", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		}, &restapi.Providers{})

		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint, nil, nil, false)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "resource query string not found")
	})

	t.Run("test resource not found", func(t *testing.T) {
		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		}, &restapi.Providers{})
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
			ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		}, &restapi.Providers{})
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
			ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		}, &restapi.Providers{})
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

	t.Run("test vct resource", func(t *testing.T) {
		const webfingerPayload = `{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct-v1"}}`

		wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(webfingerPayload)),
				StatusCode: http.StatusOK,
			}, nil
		})

		wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

		c, err := restapi.New(&restapi.Config{
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{
				WebfingerClient:      wfClient,
				LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct.com"},
			})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=http://base/vct",
			nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

		require.Equal(t, "vct", w.Links[0].Rel)
		require.Equal(t, "http://vct.com", w.Links[0].Href)
		require.Equal(t, "vct-v1", w.Properties[command.LedgerType])
	})

	t.Run("error - vct resource error", func(t *testing.T) {
		const webfingerPayload = `{}`

		wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(webfingerPayload)),
				StatusCode: http.StatusOK,
			}, nil
		})

		wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

		c, err := restapi.New(&restapi.Config{
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{
				WebfingerClient:      wfClient,
				LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct.com"},
			})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=http://base/vct",
			nil, nil, false)

		require.Equal(t, http.StatusOK, rr.Code)

		var w restapi.JRD

		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

		require.Equal(t, "vct", w.Links[0].Rel)
		require.Equal(t, "http://vct.com", w.Links[0].Href)
		require.Empty(t, w.Properties[command.LedgerType])
	})

	t.Run("error - vct internal server error", func(t *testing.T) {
		wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(" internal server error")),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

		c, err := restapi.New(&restapi.Config{
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{
				WebfingerClient:      wfClient,
				LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct.com"},
			})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+"?resource=http://base/vct",
			nil, nil, false)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("test WebCAS resource", func(t *testing.T) {
		casClient := &mocks.CASClient{}

		linkStore := &orbmocks.AnchorLinkStore{}
		linkStore.GetLinksReturns([]*url.URL{
			testutil.MustParseURL(
				"hl:uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ:uoQ-BeDVpcGZzOi8vUW1jcTZKV0RVa3l4ZWhxN1JWWmtQM052aUU0SHFSdW5SalgzOXZ1THZFSGFRTg"), //nolint:lll
		}, nil)

		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		}, &restapi.Providers{
			CAS:             casClient,
			AnchorLinkStore: linkStore,
		})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		t.Run("Success with CID", func(t *testing.T) {
			casClient.ReadReturns(nil, nil)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
			require.Len(t, w.Links, 3)
			require.Equal(t, "http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
				w.Links[0].Href)
			require.Equal(t, "http://domain1/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y",
				w.Links[1].Href)
			require.Equal(t, "ipfs://Qmcq6JWDUkyxehq7RVZkP3NviE4HqRunRjX39vuLvEHaQN",
				w.Links[2].Href)
			require.Empty(t, w.Properties)
		})

		t.Run("Success with multihash", func(t *testing.T) {
			casClient.ReadReturns(nil, nil)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/uEiATVQNQqGgchMhhqsLltEAWHCszo-TzAqxoDKW2ht5I3g", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
			require.Len(t, w.Links, 3)
			require.Equal(t, "http://base/cas/uEiATVQNQqGgchMhhqsLltEAWHCszo-TzAqxoDKW2ht5I3g",
				w.Links[0].Href)
			require.Equal(t, "http://domain1/cas/uEiATVQNQqGgchMhhqsLltEAWHCszo-TzAqxoDKW2ht5I3g",
				w.Links[1].Href)
			require.Equal(t, "ipfs://Qmcq6JWDUkyxehq7RVZkP3NviE4HqRunRjX39vuLvEHaQN",
				w.Links[2].Href)
			require.Empty(t, w.Properties)
		})

		t.Run("Resource not found", func(t *testing.T) {
			casClient.ReadReturns(nil, orberrors.ErrContentNotFound)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

			require.Equal(t, http.StatusNotFound, rr.Code)
		})

		t.Run("No resource ID in request", func(t *testing.T) {
			casClient.ReadReturns(nil, orberrors.ErrContentNotFound)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/", nil, nil, false)

			require.Equal(t, http.StatusBadRequest, rr.Code)
		})

		t.Run("CAS error", func(t *testing.T) {
			casClient.ReadReturns(nil, errors.New("injected CAS client error"))

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
		})

		t.Run("Anchor link storage error", func(t *testing.T) {
			casClient.ReadReturns(nil, nil)
			linkStore.GetLinksReturns(nil, errors.New("injected storage error"))

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

			// The alternate link won't be included due to a storage error, but it should still return results.
			require.Len(t, w.Links, 2)
		})

		t.Run("Invalid alternate hashlink", func(t *testing.T) {
			casClient.ReadReturns(nil, nil)
			linkStore.GetLinksReturns([]*url.URL{testutil.MustParseURL("xl:xxx")}, nil)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=http://base/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

			// The alternate link won't be included due to a storage error, but it should still return results.
			require.Len(t, w.Links, 2)
		})
	})

	t.Run("test did:orb resource", func(t *testing.T) {
		const anchorURI = "hl:uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ:uoQ-BeDVpcGZzOi8vUW1jcTZKV0RVa3l4ZWhxN1JWWmtQM052aUU0SHFSdW5SalgzOXZ1THZFSGFRTg" //nolint:lll

		linkStore := &orbmocks.AnchorLinkStore{}
		resourceInfoProvider := newMockResourceInfoProvider().withAnchorURI(anchorURI)

		c, err := restapi.New(&restapi.Config{
			OperationPath:             "/op",
			ResolutionPath:            "/resolve",
			WebCASPath:                "/cas",
			ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		}, &restapi.Providers{
			ResourceRegistry:     registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)),
			AnchorLinkStore:      linkStore,
			LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct.com/maple2020"},
		})
		require.NoError(t, err)

		handler := getHandler(t, c, restapi.WebFingerEndpoint)

		t.Run("Success", func(t *testing.T) {
			const canonicalRef = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"

			resourceInfoProvider.
				withAnchorURI(anchorURI).
				withCanonicalRef(canonicalRef)

			linkStore.GetLinksReturns([]*url.URL{
				testutil.MustParseURL(
					"hl:uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQlVRRFJJNXR0SXpYYmUxTFpLVWFaV2I2eUZzbk1ucmdEa3NBdFEtd0NhS3c"), //nolint:lll
			}, nil)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=did:orb:uAAA:suffix", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

			require.Len(t, w.Properties, 2)

			require.Equal(t, "MockAnchorOrigin", w.Properties["https://trustbloc.dev/ns/anchor-origin"])
			require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])

			require.Len(t, w.Links, 5)

			require.Equal(t, "self", w.Links[0].Rel)
			require.Equal(t, "application/did+ld+json", w.Links[0].Type)
			require.Equal(t, "http://base/sidetree/v1/identifiers/did:orb:uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw:suffix", //nolint:lll
				w.Links[0].Href)

			require.Equal(t, "via", w.Links[1].Rel)
			require.Equal(t, "application/ld+json", w.Links[1].Type)
			require.Equal(t, anchorURI, w.Links[1].Href)

			require.Equal(t, "service", w.Links[2].Rel)
			require.Equal(t, "application/activity+json", w.Links[2].Type)
			require.Equal(t, "http://base/services/orb", w.Links[2].Href)

			require.Equal(t, "alternate", w.Links[3].Rel)
			require.Equal(t, "application/did+ld+json", w.Links[3].Type)
			require.Equal(t, "http://domain1/sidetree/v1/identifiers/did:orb:uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw:suffix", //nolint:lll
				w.Links[3].Href)

			require.Equal(t, "alternate", w.Links[4].Rel)
			require.Equal(t, "application/did+ld+json", w.Links[4].Type)
			require.Equal(t, "https://orb.domain2.com/sidetree/v1/identifiers/did:orb:uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw:suffix", //nolint:lll
				w.Links[4].Href)
		})

		t.Run("Invalid hashlink for anchor URI", func(t *testing.T) {
			resourceInfoProvider.withAnchorURI("https://xxx")

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=did:orb:suffix", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

			require.Len(t, w.Properties, 2)

			require.Equal(t, "MockAnchorOrigin", w.Properties["https://trustbloc.dev/ns/anchor-origin"])
			require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])

			// The alternate link won't be included due to a parse error, but it should still return results.
			require.Len(t, w.Links, 4)
		})

		t.Run("Anchor link storage error", func(t *testing.T) {
			resourceInfoProvider.withAnchorURI(anchorURI)

			linkStore.GetLinksReturns(nil, errors.New("injected storage error"))

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=did:orb:suffix", nil, nil, false)

			require.Equal(t, http.StatusOK, rr.Code)

			var w restapi.JRD

			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))

			require.Len(t, w.Properties, 2)

			require.Equal(t, "MockAnchorOrigin", w.Properties["https://trustbloc.dev/ns/anchor-origin"])
			require.Equal(t, float64(2), w.Properties["https://trustbloc.dev/ns/min-resolvers"])

			// The alternate link won't be included due to a storage error, but it should still return results.
			require.Len(t, w.Links, 4)
		})

		t.Run("Anchor info retriever error", func(t *testing.T) {
			resourceInfoProvider.withAnchorURI(1000)

			rr := serveHTTP(t, handler.Handler(), http.MethodGet, restapi.WebFingerEndpoint+
				"?resource=did:orb:suffix", nil, nil, false)

			require.Equal(t, http.StatusInternalServerError, rr.Code)
		})
	})
}

func TestHostMeta(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("via /.well.known/host-meta endpoint", func(t *testing.T) {
			c, err := restapi.New(&restapi.Config{
				OperationPath:             "/op",
				ResolutionPath:            "/resolve",
				ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
				WebCASPath:                "/cas",
				DiscoveryDomains:          []string{"http://domain1"},
				DiscoveryMinimumResolvers: 2,
			}, &restapi.Providers{LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct"}})
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
				ServiceEndpointURL:        testutil.MustParseURL("http://base/services/orb"),
				WebCASPath:                "/cas",
				DiscoveryDomains:          []string{"http://domain1"},
				DiscoveryMinimumResolvers: 2,
			}, &restapi.Providers{LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct"}})
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
			WebCASPath:                "/cas",
			ServiceEndpointURL:        testutil.MustParseURL("http://example.com/services/orb"),
			DiscoveryDomains:          []string{"http://domain1"},
			DiscoveryMinimumResolvers: 2,
		}, &restapi.Providers{LogEndpointRetriever: &mockLogEndpointProvider{LogURL: "http://vct"}})
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
		ServiceEndpointURL: testutil.MustParseURL("http://example.com/services/orb"),
		WebCASPath:         "/cas",
		PubKeys:            []restapi.PublicKey{{ID: "key1", Value: []byte("value"), Type: kms.ED25519}},
	}, &restapi.Providers{})
	require.NoError(t, err)

	handler := getHandler(t, c, webDIDEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, webDIDEndpoint, nil, nil, false)

	var w ariesdid.Doc

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.ID, "did:web:example.com")
	require.Len(t, w.VerificationMethod, 1)
}

func TestWellKnownServiceDID(t *testing.T) {
	const id = "did:web:example.com:services:orb"

	c, err := restapi.New(&restapi.Config{
		ServiceEndpointURL: testutil.MustParseURL("https://example.com/services/orb"),
		ServiceID:          testutil.MustParseURL(id),
		WebCASPath:         "/cas",
		HTTPSignPubKeys:    []restapi.PublicKey{{ID: "key1", Value: []byte("value"), Type: kms.ED25519}},
	}, &restapi.Providers{})
	require.NoError(t, err)

	handler := getHandler(t, c, "/services/orb/did.json")

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, webDIDEndpoint, nil, nil, false)

	var doc ariesdid.Doc

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))
	require.Equal(t, doc.ID, id)
	require.Len(t, doc.VerificationMethod, 1)
	require.Len(t, doc.Service, 1)

	service := doc.Service[0]

	require.Equal(t, id+"#activity-pub", service.ID)
	require.Equal(t, "LinkedDomains", service.Type)

	u, err := service.ServiceEndpoint.URI()
	require.NoError(t, err)
	require.Equal(t, "https://example.com", u)
}

func TestOrbWebDIDResolver(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		didDoc := make(document.Document)

		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(&document.ResolutionResult{Document: didDoc}, nil)

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDResolverEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDResolverEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("success - port provided", func(t *testing.T) {
		didDoc := make(document.Document)

		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(&document.ResolutionResult{Document: didDoc}, nil)

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base:8080/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, "/1.0/identifiers/did:web:base%3A8080:scid:{id}")

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDResolverEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("error - resource not found", func(t *testing.T) {
		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(nil, orberrors.ErrContentNotFound)

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDResolverEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDResolverEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Contains(t, rr.Body.String(), "resource not found")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(nil, fmt.Errorf("internal error"))

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDResolverEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDResolverEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error retrieving resource")
	})
}

func TestOrbWebDIDFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		didDoc := make(document.Document)

		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(&document.ResolutionResult{Document: didDoc}, nil)

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDFileEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDFileEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("error - resource not found (invalid)", func(t *testing.T) {
		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(nil, orberrors.ErrContentNotFound)

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDFileEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDFileEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Contains(t, rr.Body.String(), "resource not found")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		wr := &endpointmocks.WebResolver{}
		wr.ResolveDocumentReturns(nil, fmt.Errorf("internal error"))

		c, err := restapi.New(&restapi.Config{
			OperationPath:      "/op",
			ResolutionPath:     "/resolve",
			WebCASPath:         "/cas",
			ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
		},
			&restapi.Providers{WebResolver: wr})
		require.NoError(t, err)

		handler := getHandler(t, c, orbWebDIDFileEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = suffix

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, orbWebDIDFileEndpoint,
			nil, urlVars, false)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error retrieving resource")
	})
}

func TestWellKnown(t *testing.T) {
	c, err := restapi.New(&restapi.Config{
		OperationPath:      "/op",
		ResolutionPath:     "/resolve",
		WebCASPath:         "/cas",
		ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
	}, &restapi.Providers{})
	require.NoError(t, err)

	handler := getHandler(t, c, didOrbEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, didOrbEndpoint, nil, nil, false)

	var w restapi.WellKnownResponse

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.OperationEndpoint, "http://base/op")
	require.Equal(t, w.ResolutionEndpoint, "http://base/resolve")
}

func TestWellKnownNodeInfo(t *testing.T) {
	c, err := restapi.New(&restapi.Config{
		OperationPath:      "/op",
		ResolutionPath:     "/resolve",
		WebCASPath:         "/cas",
		ServiceEndpointURL: testutil.MustParseURL("http://base/services/orb"),
	}, &restapi.Providers{})
	require.NoError(t, err)

	handler := getHandler(t, c, nodeInfoEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, nodeInfoEndpoint, nil, nil, false)

	require.Equal(t, http.StatusOK, rr.Code)

	t.Logf("Got response: %s", rr.Body.Bytes())

	var resp restapi.JRD

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Links, 2)
	require.Equal(t, "http://nodeinfo.diaspora.software/ns/schema/2.0", resp.Links[0].Rel)
	require.Equal(t, "http://base/nodeinfo/2.0", resp.Links[0].Href)
	require.Equal(t, "http://nodeinfo.diaspora.software/ns/schema/2.1", resp.Links[1].Rel)
	require.Equal(t, "http://base/nodeinfo/2.1", resp.Links[1].Href)
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

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}

type mockLogEndpointProvider struct {
	LogURL string
	Err    error
}

func (mle *mockLogEndpointProvider) GetLogEndpoint() (string, error) {
	if mle.Err != nil {
		return "", mle.Err
	}

	return mle.LogURL, nil
}
