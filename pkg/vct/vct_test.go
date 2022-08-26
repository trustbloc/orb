/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

//go:generate counterfeiter -o ../mocks/configretriever.gen.go --fake-name ConfigRetriever . configRetriever

// nolint: lll
const mockResponse = `{
  "svct_version": 0,
  "id": "ztrZNwAslc6QFucuV8EUuxQ37zx0EikI1yLw/cx2xeE=",
  "timestamp": 1661370164755,
  "extensions": "",
  "signature": "eyJhbGdvcml0aG0iOnsic2lnbmF0dXJlIjoiRUNEU0EiLCJ0eXBlIjoiRUNEU0FQMjU2REVSIn0sInNpZ25hdHVyZSI6Ik1FVUNJRDg5VVU3ZG1PYVhIVnVvb2JNZU5OOUgxdDJNOWhPc0FtbGpRSjNwYmxVUkFpRUEvd1RyU1cyd29NVHZuam1vdTJsQmo4em9wRWVMc05ya3F1V3JDL09adFA4PSJ9"
}`

const mockVC = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": {
    "anchor": "hl:uEiAjZSjGBTq3vCDAGjDRNuNsQvyj4XfvWd3qI7EBZN1NQA",
    "href": "hl:uEiC43VX3UtAriY_tbmjmqXWPzwYMYyy3cEWr-u3zF_EiDA",
    "profile": "https://w3id.org/orb#v0",
    "rel": "linkset",
    "type": [
      "AnchorLink"
    ]
  },
  "id": "https://orb.domain1.com/vc/fd308ff6-3211-442c-a3d0-2459bef9e3e1",
  "issuanceDate": "2022-08-24T19:42:44.745875825Z",
  "issuer": "https://orb.domain1.com",
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) { return m(req) }

func TestClient_Witness(t *testing.T) {
	const webfingerURL = "/.well-known/webfinger"

	configRetriever := &mocks.ConfigRetriever{}
	configRetriever.GetValueReturns([]byte(`{"url":"https://example.com"}`), nil)

	emptyConfigRetriever := &mocks.ConfigRetriever{}
	emptyConfigRetriever.GetValueReturns([]byte(`{"url":""}`), nil)

	t.Run("Success", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == webfingerURL {
				pubKey := `{"properties":{"https://trustbloc.dev/ns/public-key":` +
					`"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Di7Fea52hG12mc6VVhHIlbC/F2KMgh2fs6bweeHojWBCxzKoLya5ty4ZmjM5agWMyTBvfrJ4leWAlCoCV2yvA=="}}` //nolint:lll

				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString(pubKey)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(mockResponse)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)), WithAuthWriteToken("write"),
			WithAuthReadToken("read"))

		resp, err := client.Witness([]byte(mockVC))
		require.NoError(t, err)

		var p Proof
		require.NoError(t, json.Unmarshal(resp, &p))

		require.Len(t, p.Context, 1)
		timestampTime, err := time.Parse(time.RFC3339, p.Proof["created"].(string))
		require.NoError(t, err)

		require.Equal(t, int64(1661370164755000000), timestampTime.UnixNano())
	})

	t.Run("Error - endpoint retriever error", func(t *testing.T) {
		retriever := &mocks.ConfigRetriever{}
		retriever.GetValueReturns(nil, fmt.Errorf("endpoint error"))

		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == webfingerURL {
				pubKey := `{"properties":{"https://trustbloc.dev/ns/public-key":` +
					`"BL0zrdTbR4mc1ZBuaXOh52IYeYKd9hlXrB3eZ+GR9WsHHGhrNaJJB9bpEXvM4zo2vnm34nQezBJ1/a/cQS/j+Q0="}}`

				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString(pubKey)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(mockResponse)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(retriever, &mockSigner{},
			&mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)), WithAuthWriteToken("write"),
			WithAuthReadToken("read"))

		resp, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Nil(t, resp)
		require.Contains(t, err.Error(), "failed to get log endpoint for witness")
	})

	t.Run("Success (no vct)", func(t *testing.T) {
		client := New(emptyConfigRetriever, &mockSigner{}, &mocks.MetricsProvider{},
			WithDocumentLoader(testutil.GetLoader(t)))

		resp, err := client.Witness([]byte(mockVC))
		require.NoError(t, err)

		var p Proof
		require.NoError(t, json.Unmarshal(resp, &p))

		require.Len(t, p.Context, 1)
		require.Empty(t, p.Proof["domain"])
		timestampTime, err := time.Parse(time.RFC3339, p.Proof["created"].(string))
		require.NoError(t, err)

		require.NotEmpty(t, timestampTime.UnixNano())
	})
	t.Run("Parse credential (error)", func(t *testing.T) {
		client := New(emptyConfigRetriever, &mockSigner{}, &mocks.MetricsProvider{})

		_, err := client.Witness([]byte(`[]`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse credential")
	})
	t.Run("Bad signature", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == webfingerURL {
				pubKey := `{"properties":{"https://trustbloc.dev/ns/public-key":` +
					`"BMihLNkyUqmi9VOj2TywSsLwuWRNSG3CQNj7elRSunRleSsYT1BQVkKN89hW5auNFZ9v0z0MbHdytWkHARBnz4o="}}`

				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString(pubKey)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body: ioutil.NopCloser(bytes.NewBufferString(
					strings.Replace(mockResponse, "1617977793917", "1617977793918", 1)),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "verify VC timestamp signature")
	})

	t.Run("Bad public key", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			pubKey := `{"properties":{"https://trustbloc.dev/ns/public-key":10}}`

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(pubKey)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key is not a string")
	})

	t.Run("Decode public key (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			pubKey := `{"properties":{"https://trustbloc.dev/ns/public-key":"9"}}`

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(pubKey)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode public key: illegal base64 data at input byte 0")
	})

	t.Run("No public key (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{},
			WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)),
		)

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "no public key")
	})
	t.Run("Parse credential (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

		_, err := client.Witness([]byte(`[]`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse credential")
	})

	t.Run("Add VC (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"message":"error"}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "add VC: error")
	})

	t.Run("Check Health (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"message":"vct error"}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

		err := client.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct error")
	})

	t.Run("Check Health (endpoint retriever error)", func(t *testing.T) {
		configRetriever := &mocks.ConfigRetriever{}
		configRetriever.GetValueReturns(nil, fmt.Errorf("log retriever error"))

		client := New(configRetriever, &mockSigner{},
			&mocks.MetricsProvider{})

		err := client.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "log retriever error")
	})
}

func TestGetLogEndpoint(t *testing.T) {
	const logURLValue = "https://vct.com/log"

	const empty = ""

	t.Run("success - retrieve from cache and from store", func(t *testing.T) {
		logURLValueBytes, err := json.Marshal(&logCfg{URL: logURLValue})
		require.NoError(t, err)

		configRetriever := &mocks.ConfigRetriever{}
		configRetriever.GetValueReturns(logURLValueBytes, nil)

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{})

		endpoint, err := client.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, logURLValue, endpoint)
	})

	t.Run("success - empty log URL", func(t *testing.T) {
		logURLValueBytes, err := json.Marshal(&logCfg{})
		require.NoError(t, err)

		configRetriever := &mocks.ConfigRetriever{}
		configRetriever.GetValueReturns(logURLValueBytes, nil)

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{})

		endpoint, err := client.GetLogEndpoint()
		require.NoError(t, err)
		require.Equal(t, empty, endpoint)
	})

	t.Run("error - log URL not configured", func(t *testing.T) {
		configRetriever := &mocks.ConfigRetriever{}
		configRetriever.GetValueReturns(nil, orberrors.ErrContentNotFound)

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{})

		endpoint, err := client.GetLogEndpoint()
		require.True(t, errors.Is(err, ErrLogEndpointNotConfigured))
		require.Empty(t, endpoint)
	})

	t.Run("error - unmarshal log URL ", func(t *testing.T) {
		configRetriever := &mocks.ConfigRetriever{}
		configRetriever.GetValueReturns([]byte(`}`), nil)

		client := New(configRetriever, &mockSigner{}, &mocks.MetricsProvider{})

		endpoint, err := client.GetLogEndpoint()
		require.Error(t, err)
		require.Equal(t, empty, endpoint)
		require.Contains(t, err.Error(), "unmarshal log config: invalid character")
	})
}

type mockSigner struct {
	Err error
}

func (m *mockSigner) Sign(vc *verifiable.Credential, opts ...vcsigner.Opt) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	ctx := &verifiable.LinkedDataProofContext{}

	for _, opt := range opts {
		opt(ctx)
	}

	vc.Proofs = append(vc.Proofs, map[string]interface{}{
		"created": ctx.Created.Format(time.RFC3339Nano),
		"domain":  ctx.Domain,
	})

	return vc, nil
}

func (m *mockSigner) Context() []string {
	return []string{}
}
