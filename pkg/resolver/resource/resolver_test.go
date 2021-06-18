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
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/ipfs"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
)

const (
	sampleBaseURLWebFingerResponseData = `{"subject":"%s` +
		`","properties":{"https://trustbloc.dev/ns/cas":"https://testnet.orb.local/cas","https://tru` +
		`stbloc.dev/ns/min-resolvers":1,"https://trustbloc.dev/ns/vct":"https://testnet.orb.local/vct","https://` +
		`trustbloc.dev/ns/witness":"%s/services/orb"},"links":[{"rel":"self","href":"http` +
		`s://testnet.orb.local/sidetree/v1/identifiers"}]}`

	sampleWitnessWebFingerResponseData = `{"subject":"%s","links":` +
		`[{"rel":"self","type":"application/ld+json","href":"%s/services/orb"}]}`
)

func TestResolver_Resolve(t *testing.T) {
	t.Run("Success - resolved via HTTP", func(t *testing.T) {
		var numTimesMockServerHandlerHit int

		var testServerURL string

		var witnessResource string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch numTimesMockServerHandlerHit {
				case 0:
					numTimesMockServerHandlerHit++
					_, err := w.Write([]byte(fmt.Sprintf(sampleBaseURLWebFingerResponseData,
						testServerURL, testServerURL)))
					require.NoError(t, err)
				case 1:
					_, err := w.Write([]byte(fmt.Sprintf(sampleWitnessWebFingerResponseData,
						fmt.Sprintf("%s/services/orb", testServerURL), testServerURL)))
					require.NoError(t, err)
				}
			}))
		defer testServer.Close()

		testServerURL = testServer.URL
		witnessResource = fmt.Sprintf("%s/services/orb", testServerURL)

		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.Resolve(fmt.Sprintf("%s/services/orb", testServerURL),
			discoveryrest.WitnessType)
		require.NoError(t, err)
		require.Equal(t, witnessResource, resource)
	})
	t.Run("Success - resolved via IPNS", func(t *testing.T) {
		var numTimesMockServerHandlerHit int

		var testServerURL string

		var witnessResource string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch numTimesMockServerHandlerHit {
				case 0:
					numTimesMockServerHandlerHit++
					_, err := w.Write([]byte(fmt.Sprintf(sampleBaseURLWebFingerResponseData,
						"ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek", testServerURL)))
					require.NoError(t, err)
				case 1:
					_, err := w.Write([]byte(fmt.Sprintf(sampleWitnessWebFingerResponseData,
						witnessResource, testServerURL)))
					require.NoError(t, err)
				}
			}))
		defer testServer.Close()

		testServerURL = testServer.URL
		witnessResource = fmt.Sprintf("%s/services/orb", testServerURL)

		resolver := resourceresolver.New(http.DefaultClient, ipfs.New(testServer.URL))

		resource, err := resolver.Resolve("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.WitnessType)
		require.NoError(t, err)
		require.Equal(t, witnessResource, resource)
	})
	t.Run("Fail to resolve via HTTP (missing protocol scheme)", func(t *testing.T) {
		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.Resolve("BadURLName", discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to get WebFinger response from HTTP/HTTPS URL: "+
			"failed to do WebFinger via REST: failed to get WebFinger response: parse "+
			`":///.well-known/webfinger?resource=:%2F%2F": missing protocol scheme`)
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (IPFS node not reachable)", func(t *testing.T) {
		resolver := resourceresolver.New(nil, ipfs.New("SomeIPFSNodeURL"))

		resource, err := resolver.Resolve("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.WitnessType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get WebFinger response from IPNS URL: "+
			`failed to read from IPNS: Post "http://SomeIPFSNodeURL/api/v0/cat?arg=%2Fipns%2Fk51qzi5uqu5dgjc`+
			`eyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek%2F.well-known%2Fwebfinger": dial tcp: `+
			"lookup SomeIPFSNodeURL:")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (WebFinger response unmarshal failure)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer testServer.Close()

		resolver := resourceresolver.New(nil, ipfs.New(testServer.URL))

		resource, err := resolver.Resolve("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to get WebFinger response from IPNS URL: "+
			"failed to unmarshal WebFinger response: unexpected end of JSON input")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via IPNS (property missing)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var webFingerResp discoveryrest.WebFingerResponse

				err := json.Unmarshal([]byte(sampleBaseURLWebFingerResponseData), &webFingerResp)
				require.NoError(t, err)

				delete(webFingerResp.Properties, discoveryrest.WitnessType)

				webFingerRespBytes, errMarshal := json.Marshal(webFingerResp)
				require.NoError(t, errMarshal)

				_, err = w.Write(webFingerRespBytes)
				require.NoError(t, err)
			}))
		defer testServer.Close()

		resolver := resourceresolver.New(nil, ipfs.New(testServer.URL))

		resource, err := resolver.Resolve("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to resolve resource from Base URL WebFinger response: "+
			"property missing")
		require.Empty(t, resource)
	})
	t.Run("Fail to assert property as a string", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var webFingerResp discoveryrest.WebFingerResponse

				err := json.Unmarshal([]byte(sampleBaseURLWebFingerResponseData), &webFingerResp)
				require.NoError(t, err)

				webFingerResp.Properties[discoveryrest.WitnessType] = 0

				webFingerRespBytes, errMarshal := json.Marshal(webFingerResp)
				require.NoError(t, errMarshal)

				_, err = w.Write(webFingerRespBytes)
				require.NoError(t, err)
			}))
		defer testServer.Close()

		resolver := resourceresolver.New(nil, ipfs.New(testServer.URL))

		resource, err := resolver.Resolve("ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to resolve resource from Base URL WebFinger response: "+
			"failed to assert property as a string")
		require.Empty(t, resource)
	})
	t.Run("Fail to resolve via HTTP (received status code 500 on first WebFinger)", func(t *testing.T) {
		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
		defer testServer.Close()

		escapedTestServerURL := url.PathEscape(testServer.URL)

		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.Resolve(testServer.URL, discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to get WebFinger response from HTTP/HTTPS URL: "+
			"failed to do WebFinger via REST: got status code 500 from "+testServer.URL+"/.well-known/webfinger?"+
			"resource="+escapedTestServerURL+" (expected 200)")
		require.Empty(t, resource)
	})
	t.Run("Fail to parse WebFinger URL from base URL WebFinger response", func(t *testing.T) {
		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(fmt.Sprintf(sampleBaseURLWebFingerResponseData,
					testServerURL, "%")))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.Resolve(fmt.Sprintf("%s/services/orb", testServerURL),
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to resolve resource from Base URL WebFinger response: "+
			"failed to get resource from property WebFinger: failed to parse property WebFinger URL: "+
			`parse "%/services/orb": invalid URL escape "%/s"`)
		require.Empty(t, resource)
	})
	t.Run("Fail to get second WebFinger response (missing protocol scheme)", func(t *testing.T) {
		var numTimesMockServerHandlerHit int

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch numTimesMockServerHandlerHit {
				case 0:
					numTimesMockServerHandlerHit++
					_, err := w.Write([]byte(fmt.Sprintf(sampleBaseURLWebFingerResponseData,
						testServerURL, "BadURL")))
					require.NoError(t, err)
				case 1:
					_, err := w.Write([]byte(fmt.Sprintf(sampleWitnessWebFingerResponseData,
						fmt.Sprintf("%s/services/orb", testServerURL), testServerURL)))
					require.NoError(t, err)
				}
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		resolver := resourceresolver.New(http.DefaultClient, nil)

		resource, err := resolver.Resolve(fmt.Sprintf("%s/services/orb", testServerURL),
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to resolve resource from Base URL WebFinger response: "+
			"failed to get resource from property WebFinger: failed to do WebFinger via REST: "+
			`failed to get WebFinger response: parse ":///.well-known/webfinger?resource=BadURL%2Fservices%2Forb": `+
			"missing protocol scheme")
		require.Empty(t, resource)
	})
	t.Run("Fail to get second WebFinger response (status code 500)", func(t *testing.T) {
		var numTimesMockServerHandlerHit int

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch numTimesMockServerHandlerHit {
				case 0:
					numTimesMockServerHandlerHit++
					_, err := w.Write([]byte(fmt.Sprintf(sampleBaseURLWebFingerResponseData,
						testServerURL, testServerURL)))
					require.NoError(t, err)
				case 1:
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		resolver := resourceresolver.New(http.DefaultClient, nil)

		escapedTestServerURL := url.PathEscape(testServer.URL)

		resource, err := resolver.Resolve(fmt.Sprintf("%s/services/orb", testServerURL),
			discoveryrest.WitnessType)
		require.EqualError(t, err, "failed to resolve resource from Base URL WebFinger response: "+
			"failed to get resource from property WebFinger: failed to do WebFinger via REST: "+
			"got status code 500 from "+testServer.URL+"/.well-known/webfinger?resource="+escapedTestServerURL+
			"%2Fservices%2Forb (expected 200)")
		require.Empty(t, resource)
	})
}
