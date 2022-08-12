/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/ipfs"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

//go:generate counterfeiter -o ../../mocks/domainResolver.gen.go --fake-name DomainResolver . domainResolver

func TestNew(t *testing.T) {
	t.Run("Success - defaults", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})
		require.Equal(t, resolver.cacheLifetime, defaultCacheLifetime)
		require.Equal(t, resolver.cacheSize, defaultCacheSize)
	})
	t.Run("Success - with options", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{},
			WithCacheLifetime(2*time.Second), WithCacheSize(500))
		require.Equal(t, resolver.cacheLifetime, 2*time.Second)
		require.Equal(t, resolver.cacheSize, 500)
	})
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("Success - resolved via HTTP", func(t *testing.T) {
		var testServerURL string

		var witnessResource string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL
		witnessResource = fmt.Sprintf("%s/services/orb", testServerURL)

		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{}, WithCacheLifetime(2*time.Second))

		resource, err := resolver.ResolveHostMetaLink(fmt.Sprintf("%s/services/orb", testServerURL),
			discoveryrest.ActivityJSONType)
		require.NoError(t, err)
		require.Equal(t, witnessResource, resource)
	})
	t.Run("Success - resolved via IPNS", func(t *testing.T) {
		var testServerURL string

		var witnessResource string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL
		witnessResource = fmt.Sprintf("%s/services/orb", testServerURL)

		resolver := New(http.DefaultClient, ipfs.New(testServer.URL, 5*time.Second, 0, &orbmocks.MetricsProvider{}),
			&orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.NoError(t, err)
		require.Equal(t, witnessResource, resource)
	})
	t.Run("Success - resolved via DID", func(t *testing.T) {
		var testServerURL string

		var witnessResource string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL
		witnessResource = fmt.Sprintf("%s/services/orb", testServerURL)

		t.Run("Success", func(t *testing.T) {
			domainResolver := &orbmocks.DomainResolver{}
			domainResolver.ResolveDomainForDIDReturns(testServerURL, nil)

			resolver := New(http.DefaultClient, nil, domainResolver, WithCacheLifetime(2*time.Second))

			resource, err := resolver.ResolveHostMetaLink("did:web:example.com:services:orb",
				discoveryrest.ActivityJSONType)
			require.NoError(t, err)
			require.Equal(t, witnessResource, resource)
		})

		t.Run("Resolve domain error", func(t *testing.T) {
			errExpected := errors.New("injected domain resolver error")

			domainResolver := &orbmocks.DomainResolver{}
			domainResolver.ResolveDomainForDIDReturns("", errExpected)

			resolver := New(http.DefaultClient, nil, domainResolver, WithCacheLifetime(2*time.Second))

			_, err := resolver.ResolveHostMetaLink("did:web:example.com:services:orb",
				discoveryrest.ActivityJSONType)
			require.Error(t, err)
			require.Contains(t, err.Error(), errExpected.Error())
		})

		t.Run("HTTP error", func(t *testing.T) {
			domainResolver := &orbmocks.DomainResolver{}
			domainResolver.ResolveDomainForDIDReturns("%", nil)

			resolver := New(http.DefaultClient, nil, domainResolver, WithCacheLifetime(2*time.Second))

			_, err := resolver.ResolveHostMetaLink("did:web:example.com:services:orb",
				discoveryrest.ActivityJSONType)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to parse given URL")
		})
	})
	t.Run("Fail to resolve via HTTP (missing protocol scheme)", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("BadURLName", discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(), "missing protocol scheme")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve (unsupported protocol scheme)", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("xxx://BadURLName", discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (IPFS node not reachable)", func(t *testing.T) {
		resolver := New(nil, ipfs.New("SomeIPFSNodeURL", 5*time.Second, 0, &orbmocks.MetricsProvider{}),
			&orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			`failed to read from IPNS: cat IPFS of CID `+
				`[/ipns/k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek/.well-known/host-meta.json]: `+
				`Post "http://SomeIPFSNodeURL/api/v0/cat?arg=%2Fipns%2Fk51qzi5uqu5dgjc`+
				`eyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek%2F.well-known%2Fhost-meta.json": dial tcp: `+
				"lookup SomeIPFSNodeURL:")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (response unmarshal failure)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer testServer.Close()

		resolver := New(nil, ipfs.New(testServer.URL, 5*time.Second, 0, &orbmocks.MetricsProvider{}),
			&orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(),
			"failed to unmarshal response into a host-meta document: unexpected end of JSON input")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (no links with the given type found)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				responseBytes, errMarshal := json.Marshal(discoveryrest.JRD{})
				require.NoError(t, errMarshal)

				_, err := w.Write(responseBytes)
				require.NoError(t, err)
			}))
		defer testServer.Close()

		resolver := New(nil, ipfs.New(testServer.URL, 5*time.Second, 0, &orbmocks.MetricsProvider{}),
			&orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.EqualError(t, err, "no links with type application/activity+json were found via "+
			"ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via HTTP (received status code 500)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
		defer testServer.Close()

		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink(testServer.URL, discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(),
			"got status code 500 from "+testServer.URL+"/.well-known/host-meta.json (expected 200)")
		require.Empty(t, resource)
	})
	t.Run("Fail to parse url", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("%", discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(),
			`parse "%": invalid URL escape "%"`)
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS since IPNS is not enabled", func(t *testing.T) {
		resolver := New(http.DefaultClient, nil, &orbmocks.DomainResolver{})

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.Contains(t, err.Error(), "unable to resolve since IPFS is not enabled")
		require.Empty(t, resource)
	})
}

func generateValidExampleHostMetaResponse(t *testing.T, hostnameInResponse string) []byte {
	t.Helper()

	hostMetaResponse := discoveryrest.JRD{
		Subject:    "",
		Properties: nil,
		Links: []discoveryrest.Link{
			{
				Type: discoveryrest.ActivityJSONType,
				Href: fmt.Sprintf("%s/services/orb", hostnameInResponse),
			},
		},
	}

	hostMetaResponseBytes, err := json.Marshal(hostMetaResponse)
	require.NoError(t, err)

	return hostMetaResponseBytes
}
