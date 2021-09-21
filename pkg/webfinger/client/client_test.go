/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/resolver/mocks"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

func TestNew(t *testing.T) {
	t.Run("success - defaults", func(t *testing.T) {
		c := New()

		require.NotNil(t, c.httpClient)
		require.Equal(t, 300*time.Second, c.cacheLifetime)
	})

	t.Run("success - options", func(t *testing.T) {
		c := New(WithHTTPClient(http.DefaultClient),
			WithCacheLifetime(5*time.Second),
			WithCacheSize(1000))

		require.Equal(t, http.DefaultClient, c.httpClient)
		require.Equal(t, 5*time.Second, c.cacheLifetime)
		require.Equal(t, 1000, c.cacheSize)
	})
}

func TestGetLedgerType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)
	})

	t.Run("success - cache entry expired", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient), WithCacheLifetime(2*time.Second))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)

		lt, err = c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)

		// sleep for 3 seconds so that cache entry expires
		time.Sleep(3 * time.Second)

		lt, err = c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)
	})

	t.Run("error - http.Do() error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("http.Do() error")
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "http.Do() error")
	})

	t.Run("error - ledger type not a string", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type": 100}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "ledger type 'float64' is not a string")
	})

	t.Run("error - no ledger type property", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "resource not found")
	})

	t.Run("error - resource not found", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString("not found")),
				StatusCode: http.StatusNotFound,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "resource not found")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString("internal server error"),
				),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))
		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "status code [500], response body [internal server error]")
	})
}

func TestHasSupportedLedgerType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct-v1"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.True(t, supported)
	})

	t.Run("success - ledger type not supported", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.False(t, supported)
	})

	t.Run("success - no ledger type not found", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.False(t, supported)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString("internal server error"),
				),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.False(t, supported)
		require.Contains(t, err.Error(), "status code [500], response body [internal server error]")
	})
}

func TestResolveWebFingerResource(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		router := mux.NewRouter()

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		operations, err := discoveryrest.New(
			&discoveryrest.Config{BaseURL: testServer.URL, WebCASPath: "/cas"},
			&discoveryrest.Providers{CAS: &mocks.CASClient{}, AnchorLinkStore: &orbmocks.AnchorLinkStore{}},
		)
		require.NoError(t, err)

		router.HandleFunc(operations.GetRESTHandlers()[1].Path(), operations.GetRESTHandlers()[1].Handler())

		client := New()

		webFingerResponse, err := client.ResolveWebFingerResource(testServer.URL,
			fmt.Sprintf("%s/cas/%s", testServer.URL, "SomeCID"))
		require.NoError(t, err)

		require.Len(t, webFingerResponse.Links, 1)
		require.Equal(t, "self", webFingerResponse.Links[0].Rel)
		require.Equal(t, fmt.Sprintf("%s/cas/SomeCID", testServer.URL), webFingerResponse.Links[0].Href)
		require.Empty(t, webFingerResponse.Properties)
	})
	t.Run("Fail to do GET call", func(t *testing.T) {
		client := New()

		webFingerResponse, err := client.ResolveWebFingerResource("NonExistentDomain",
			fmt.Sprintf("%s/cas/%s", "NonExistentDomain", "SomeCID"))
		require.EqualError(t, err, "failed to get response (URL: NonExistentDomain/.well-known/webfinger?"+
			`resource=NonExistentDomain/cas/SomeCID): Get "NonExistentDomain/.well-known/webfinger?resource=NonEx`+
			`istentDomain/cas/SomeCID": unsupported protocol scheme ""`)
		require.Empty(t, webFingerResponse)
	})
	t.Run("Received unexpected status code", func(t *testing.T) {
		router := mux.NewRouter()

		router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
			_, errWrite := rw.Write([]byte("unknown failure"))
			require.NoError(t, errWrite)
		})

		// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		client := New()

		webFingerResponse, err := client.ResolveWebFingerResource(testServer.URL,
			fmt.Sprintf("%s/cas/%s", testServer.URL, "SomeCID"))
		require.EqualError(t, err, fmt.Sprintf("received unexpected status code. URL [%s/.well-known"+
			"/webfinger?resource=%s/cas/SomeCID], status code [500], response body [unknown failu"+
			"re]", testServer.URL, testServer.URL))
		require.Empty(t, webFingerResponse)
	})
	t.Run("Response isn't a valid WebFinger response object", func(t *testing.T) {
		router := mux.NewRouter()

		router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
			_, errWrite := rw.Write([]byte("this can't be unmarshalled to a JRD"))
			require.NoError(t, errWrite)
		})

		// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		client := New()

		webFingerResponse, err := client.ResolveWebFingerResource(testServer.URL,
			fmt.Sprintf("%s/cas/%s", testServer.URL, "SomeCID"))
		require.EqualError(t, err, "failed to unmarshal WebFinger response: invalid character "+
			"'h' in literal true (expecting 'r')")
		require.Empty(t, webFingerResponse)
	})
}

func TestGetWebCASURL(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		router := mux.NewRouter()

		// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		operations, err := discoveryrest.New(
			&discoveryrest.Config{BaseURL: testServer.URL, WebCASPath: "/cas"},
			&discoveryrest.Providers{CAS: &mocks.CASClient{}, AnchorLinkStore: &orbmocks.AnchorLinkStore{}},
		)
		require.NoError(t, err)

		router.HandleFunc(operations.GetRESTHandlers()[1].Path(), operations.GetRESTHandlers()[1].Handler())

		webFingerClient := New()

		webCASURL, err := webFingerClient.GetWebCASURL(testServer.URL, "SomeCID")
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("%s/cas/SomeCID", testServer.URL), webCASURL.String())
	})
	t.Run("fail to get WebFinger response", func(t *testing.T) {
		webFingerClient := New()

		webCASURL, err := webFingerClient.GetWebCASURL("NonExistentDomain", "SomeCID")
		require.EqualError(t, err, "failed to get WebFinger resource: failed to get response "+
			`(URL: NonExistentDomain/.well-known/webfinger?resource=NonExistentDomain/cas/SomeCID): `+
			`Get "NonExistentDomain/.well-known/webfinger?resource=NonExistentDomain/cas/SomeCID": `+
			`unsupported protocol scheme ""`)
		require.Nil(t, webCASURL)
	})
	t.Run("WebCAS URL from response can't be parsed as a URL", func(t *testing.T) {
		router := mux.NewRouter()

		router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
			webFingerResponse := discoveryrest.JRD{Links: []discoveryrest.Link{
				{Rel: "self", Href: "%"},
			}}
			webFingerResponseBytes, errMarshal := json.Marshal(webFingerResponse)
			require.NoError(t, errMarshal)

			_, errWrite := rw.Write(webFingerResponseBytes)
			require.NoError(t, errWrite)
		})

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		webFingerClient := New()

		data, err := webFingerClient.GetWebCASURL(testServer.URL, "SomeCID")
		require.EqualError(t, err, `failed to parse webcas URL: parse "%": invalid URL escape "%"`)
		require.Nil(t, data)
	})
}

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}
