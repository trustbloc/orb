/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	vdrmocks "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

const (
	ipnsURL = "ipns://wwrrww"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)
		require.NotNil(t, cs)

		require.Equal(t, defaultCacheLifetime, cs.cacheLifetime)
		require.Equal(t, defaultCacheSize, cs.cacheSize)
	})

	t.Run("success - with cache options", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{},
			WithAuthToken("t1"),
			WithCacheSize(500),
			WithCacheLifetime(time.Minute))
		require.NoError(t, err)
		require.NotNil(t, cs)

		require.Equal(t, time.Minute, cs.cacheLifetime)
		require.Equal(t, 500, cs.cacheSize)
	})

	t.Run("success - with public key fetcher", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{},
			WithAuthToken("t1"),
			WithPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{}, nil
			}),
		)
		require.NoError(t, err)
		require.NotNil(t, cs)

		require.Equal(t, defaultCacheLifetime, cs.cacheLifetime)
		require.Equal(t, defaultCacheSize, cs.cacheSize)
	})
}

func TestConfigService_GetEndpointAnchorOrigin(t *testing.T) {
	t.Run("test wrong did - doesn't match default namespace (did:orb)", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must start with configured namespace")
	})

	t.Run("test wrong did - doesn't match provided namespace", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithNamespace("did:other"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must start with configured namespace")
	})

	t.Run("test wrong did - no namespace", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "must start with configured namespace")
	})

	t.Run("test wrong did - wrong number of parts", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of parts for [cid:suffix] combo")
	})

	t.Run("test wrong did - wrong number of parts", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:cid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of parts for [cid:suffix] combo")
	})

	t.Run("test wrong did - wrong number of parts", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:cid:")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did suffix is empty")
	})

	t.Run("test error from orb client", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return nil, fmt.Errorf("failed to get anchor origin")
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get anchor origin")
	})

	t.Run("test get anchor origin return not string", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return []byte(""), nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get anchor origin didn't return string")
	})

	t.Run("test get anchor origin return not ipns", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return "wrong", nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchorOrigin wrong not supported")
	})

	t.Run("test get anchor origin return https", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthTokenProvider(&tokenProvider{}))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return "https://localhost", nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "https://localhost/.well-known")
	})

	t.Run("test error fetch ipns webfinger", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return ipnsURL, nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
	})

	t.Run("test error origin property not string", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.httpClient = &mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Path, "ipns/wwrrww/.well-known/host-meta.json") {
				b, errMarshal := json.Marshal(restapi.JRD{})
				require.NoError(t, errMarshal)
				r := io.NopCloser(bytes.NewReader(b))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}

			return nil, nil //nolint:nilnil
		}}

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return ipnsURL, nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to find template url in webfinger doc")
	})

	t.Run("test error get template webfinger", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.httpClient = &mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Path, "ipns/wwrrww/.well-known/host-meta.json") {
				b, errMarshal := json.Marshal(restapi.JRD{Links: []restapi.Link{{
					Rel:      "self",
					Template: "https://localhost/.well-known/webfinger?resource={uri}",
					Type:     "application/jrd+json",
				}}})
				require.NoError(t, errMarshal)
				r := io.NopCloser(bytes.NewReader(b))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			} else if strings.Contains(req.URL.Path, ".well-known/webfinger") {
				return nil, fmt.Errorf("failed to get template webfinger")
			}

			return nil, nil //nolint:nilnil
		}}

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return ipnsURL, nil
		}}

		_, err = cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get template webfinger")
	})

	t.Run("success", func(t *testing.T) {
		cs, err := New(nil, &mocks.CasClient{}, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.httpClient = &mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Path, "ipns/wwrrww/.well-known/host-meta.json") {
				b, errMarshal := json.Marshal(restapi.JRD{Links: []restapi.Link{{
					Rel:      "self",
					Template: "https://localhost/.well-known/webfinger?resource={uri}",
					Type:     "application/jrd+json",
				}}})
				require.NoError(t, errMarshal)
				r := io.NopCloser(bytes.NewReader(b))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}
			if strings.Contains(req.URL.Path, ".well-known/webfinger") {
				fmt.Println(req.URL.Path)
				b, errMarshal := json.Marshal(restapi.JRD{
					Properties: map[string]interface{}{
						minResolvers:         float64(2),
						anchorOriginProperty: ipnsURL,
					},
					Links: []restapi.Link{
						{Href: "https://localhost/resolve1/did:orb:ipfs:a:123", Rel: "self", Type: "application/did+ld+json"},
						{Href: "https://localhost/resolve2/did:orb:ipfs:a:123", Rel: "alternate", Type: "application/did+ld+json"},
						{Href: "ipfs:cid", Rel: "via", Type: "application/ld+json"},
					},
				})

				require.NoError(t, errMarshal)
				r := io.NopCloser(bytes.NewReader(b))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}

			return nil, nil //nolint:nilnil
		}}

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return ipnsURL, nil
		}}

		endpoint, err := cs.GetEndpointFromAnchorOrigin("did:orb:ipfs:a:123")
		require.NoError(t, err)
		require.Equal(t, "https://localhost/resolve1", endpoint.ResolutionEndpoints[0])
		require.Equal(t, "https://localhost/resolve2", endpoint.ResolutionEndpoints[1])
		require.Equal(t, "ipfs:cid", endpoint.AnchorURI)
	})
}

func TestConfigService_GetEndpoint(t *testing.T) { //nolint: gocyclo,gocognit,cyclop,maintidx
	t.Run("success", func(t *testing.T) {
		const domain = "https://example.com"

		vdr := &vdrmocks.MockVDRegistry{
			ResolveValue: &did.Doc{
				Service: []did.Service{
					{
						Type:            serviceTypeLinkedDomains,
						ServiceEndpoint: model.NewDIDCoreEndpoint([]string{domain}),
					},
				},
			},
		}

		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithVDR(vdr),
			WithHTTPClient(
				&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.Path, ".well-known/did-orb") {
						b, err := json.Marshal(restapi.WellKnownResponse{
							OperationEndpoint:  "https://localhost/op",
							ResolutionEndpoint: "https://localhost/resolve1",
						})
						require.NoError(t, err)
						r := io.NopCloser(bytes.NewReader(b))

						return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
					}

					if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
						strings.Contains(req.URL.RawQuery, "op") {
						b, err := json.Marshal(restapi.JRD{
							Links: []restapi.Link{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
						})
						require.NoError(t, err)
						r := io.NopCloser(bytes.NewReader(b))

						return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
					}

					if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
						strings.Contains(req.URL.RawQuery, "resolve1") {
						b, err := json.Marshal(restapi.JRD{
							Properties: map[string]interface{}{minResolvers: float64(2)},
							Links: []restapi.Link{
								{Href: "https://localhost/resolve1", Rel: "self"},
								{Href: "https://localhost/resolve2", Rel: "alternate"},
							},
						})
						require.NoError(t, err)
						r := io.NopCloser(bytes.NewReader(b))

						return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
					}

					if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
						strings.Contains(req.URL.RawQuery, "resolve2") {
						b, err := json.Marshal(restapi.JRD{
							Properties: map[string]interface{}{minResolvers: float64(2)},
							Links: []restapi.Link{
								{Href: "https://localhost/resolve2", Rel: "self"},
								{Href: "https://localhost/resolve1", Rel: "alternate"},
							},
						})
						require.NoError(t, err)
						r := io.NopCloser(bytes.NewReader(b))

						return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
					}

					return nil, nil //nolint:nilnil
				}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"https://localhost/resolve1", "https://localhost/resolve2"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"https://localhost/op1", "https://localhost/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)

		endpoint, err = cs.GetEndpoint("did:web:example.com:services:orb")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"https://localhost/resolve1", "https://localhost/resolve2"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"https://localhost/op1", "https://localhost/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("failed to fetch webfinger links", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(bytes.NewReader([]byte{})),
					}, nil
				}

				return nil, nil //nolint:nilnil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from "+
			"https://localhost/.well-known/webfinger?resource=https:%2F%2Flocalhost%2Fresolve2 status")
	})

	t.Run("webfinger link return different min resolver", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.JRD{
						Links: []restapi.Link{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(3)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve2", Rel: "self"},
							{Href: "https://localhost/resolve1", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil //nolint:nilnil
			}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"https://localhost/resolve1"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"https://localhost/op1", "https://localhost/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("webfinger link return different list of endpoints", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.JRD{
						Links: []restapi.Link{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve2", Rel: "self"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil //nolint:nilnil
			}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, []string{"https://localhost/resolve1"}, endpoint.ResolutionEndpoints)
		require.Equal(t, []string{"https://localhost/op1", "https://localhost/op2"}, endpoint.OperationEndpoints)
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("fail to send request for well-known", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("failed to send")
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send")
	})

	t.Run("well-known return 500 status", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from https://d1/.well-known/did-orb status")
	})

	t.Run("web finger resolution return 500 status", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithDisableProofCheck(true), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve",
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from https://localhost/.well-known"+
				"/webfinger?resource=https:%2F%2Flocalhost%2Fresolve status")
	})

	t.Run("web finger operation return 500 status", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve",
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve") {
					b, err := json.Marshal(restapi.JRD{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.Link{
							{Href: "https://localhost/resolve1"},
							{Href: "https://localhost/resolve2"},
						},
					})
					require.NoError(t, err)
					r := io.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from https://localhost/.well-known/"+
				"webfinger?resource=https:%2F%2Flocalhost%2Fop status")
	})
}

func TestDefaultCASReader(t *testing.T) {
	t.Run("success - no hint", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				r := io.NopCloser(bytes.NewReader([]byte("{}")))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}}))
		require.NoError(t, err)

		r := &referenceCASReaderImplementation{s: cs}

		val, err := r.Read("cid")
		require.NoError(t, err)
		require.NotNil(t, val)
	})

	t.Run("success - ipfs hint", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				r := io.NopCloser(bytes.NewReader([]byte("{}")))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}}))
		require.NoError(t, err)

		r := &referenceCASReaderImplementation{s: cs}

		val, err := r.Read("ipfs:cid")
		require.NoError(t, err)
		require.NotNil(t, val)
	})

	t.Run("error - webcas hint not implemented yet", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{},
			WithAuthToken("t1"), WithHTTPClient(
				&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
					r := io.NopCloser(bytes.NewReader([]byte("{}")))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}}))
		require.NoError(t, err)

		r := &referenceCASReaderImplementation{s: cs}

		val, err := r.Read("webcas:cid")
		require.Error(t, err)
		require.Nil(t, val)
		require.Contains(t, err.Error(), "hint 'webcas' will be supported soon")
	})

	t.Run("error - hint not supported", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				r := io.NopCloser(bytes.NewReader([]byte("{}")))

				return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
			}}))
		require.NoError(t, err)

		r := &referenceCASReaderImplementation{s: cs}

		val, err := r.Read("invalid:cid")
		require.Error(t, err)
		require.Nil(t, val)
		require.Contains(t, err.Error(), "hint 'invalid' not supported")
	})

	t.Run("error - ipfs resolver error", func(t *testing.T) {
		cs, err := New(nil, &referenceCASReaderImplementation{}, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				r := io.NopCloser(bytes.NewReader([]byte("error")))

				return &http.Response{StatusCode: http.StatusInternalServerError, Body: r}, nil
			}}))
		require.NoError(t, err)

		r := &referenceCASReaderImplementation{s: cs}

		val, err := r.Read("ipfs:cid")
		require.Error(t, err)
		require.Nil(t, val)
		require.Contains(t, err.Error(),
			"failed to resolve cidWithHint[ipfs cid]: got unexpected response from https://ipfs.io/ipfs/cid status '500' body error")
	})
}

func TestClient_ResolveDomainForDID(t *testing.T) {
	const (
		id     = "did:web:example.com:services:orb"
		domain = "https://example.com"
	)

	t.Run("Success", func(t *testing.T) {
		vdr := &vdrmocks.MockVDRegistry{
			ResolveValue: &did.Doc{
				Service: []did.Service{
					{
						Type:            serviceTypeLinkedDomains,
						ServiceEndpoint: model.NewDIDCoreEndpoint([]string{domain}),
					},
				},
			},
		}

		c, err := New(nil, &referenceCASReaderImplementation{}, WithVDR(vdr))
		require.NoError(t, err)
		require.NotNil(t, c)

		d, err := c.ResolveDomainForDID(id)
		require.NoError(t, err)
		require.Equal(t, domain, d)
	})

	t.Run("VDR error", func(t *testing.T) {
		vdr := &vdrmocks.MockVDRegistry{
			ResolveErr: errors.New("injected VDR error"),
		}

		c, err := New(nil, &referenceCASReaderImplementation{}, WithVDR(vdr))
		require.NoError(t, err)
		require.NotNil(t, c)

		_, err = c.ResolveDomainForDID(id)
		require.Error(t, err)
		require.Contains(t, err.Error(), vdr.ResolveErr.Error())
	})
}

type mockHTTPClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Get(context.Context, *transport.Request) (*http.Response, error) {
	panic("implement me")
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}

	return nil, nil //nolint:nilnil
}

type mockOrbClient struct {
	getAnchorOriginFunc func(cid, suffix string) (interface{}, error)
}

func (m *mockOrbClient) GetAnchorOrigin(cid, suffix string) (interface{}, error) {
	if m.getAnchorOriginFunc != nil {
		return m.getAnchorOriginFunc(cid, suffix)
	}

	return nil, nil //nolint:nilnil
}

type tokenProvider struct{}

func (t *tokenProvider) AuthToken() (string, error) {
	return "newTK", nil
}
