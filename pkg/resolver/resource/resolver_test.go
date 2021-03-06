/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/ipfs"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
)

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

		resolver := resourceresolver.New(http.DefaultClient, nil)

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

		resolver := resourceresolver.New(http.DefaultClient, ipfs.New(testServer.URL))

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.NoError(t, err)
		require.Equal(t, witnessResource, resource)
	})
	t.Run("Fail to resolve via HTTP (missing protocol scheme)", func(t *testing.T) {
		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.ResolveHostMetaLink("BadURLName", discoveryrest.ActivityJSONType)
		require.EqualError(t, err, "failed to get host-meta document via HTTP/HTTPS: "+
			"failed to get a response from the host-meta endpoint: parse "+
			`":///.well-known/host-meta.json": missing protocol scheme`)
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (IPFS node not reachable)", func(t *testing.T) {
		resolver := resourceresolver.New(nil, ipfs.New("SomeIPFSNodeURL"))

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get host-meta document via IPNS: "+
			`failed to read from IPNS: Post "http://SomeIPFSNodeURL/api/v0/cat?arg=%2Fipns%2Fk51qzi5uqu5dgjc`+
			`eyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek%2F.well-known%2Fhost-meta.json": dial tcp: `+
			"lookup SomeIPFSNodeURL:")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (response unmarshal failure)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer testServer.Close()

		resolver := resourceresolver.New(nil, ipfs.New(testServer.URL))

		resource, err := resolver.ResolveHostMetaLink("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.ActivityJSONType)
		require.EqualError(t, err, "failed to get host-meta document via IPNS: "+
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

		resolver := resourceresolver.New(nil, ipfs.New(testServer.URL))

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

		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.ResolveHostMetaLink(testServer.URL, discoveryrest.ActivityJSONType)
		require.EqualError(t, err, "failed to get host-meta document via HTTP/HTTPS: "+
			"got status code 500 from "+testServer.URL+"/.well-known/host-meta.json (expected 200)")
		require.Empty(t, resource)
	})
	t.Run("Fail to parse url", func(t *testing.T) {
		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.ResolveHostMetaLink("%", discoveryrest.ActivityJSONType)
		require.EqualError(t, err, "failed to get host-meta document via HTTP/HTTPS: "+
			`failed to parse given URL: parse "%": invalid URL escape "%"`)
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
