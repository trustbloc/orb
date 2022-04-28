/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/vcsigner"
	. "github.com/trustbloc/orb/pkg/vct"
)

// nolint: lll
const mockResponse = `{
   "svct_version":0,
   "id":"H+IApArXUZ8NAcq8Vjr1t86aY5dpBQoCDc1wodEwXvI=",
   "timestamp":1627462750739,
   "extensions":"",
   "signature":"eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiJYNHB4eEZXdFl5ckZvSTIzU0NCZ2FpcVhndm1NdEJTUlJGbzEyUFpOU0c3ckFUMHBXUkR4WjRMcVJWQmJESllSNXQ3bXViUy9vUlIwaG5RSm81NlFCQT09In0="
}`

// nolint: lll
const mockVC = `{
  "@context":[
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "credentialSubject":{
    "degree":{
      "name":"Bachelor of Science and Arts",
      "type":"BachelorDegree"
    },
    "id":"did:key:z5TcESXuYUE9aZWYwSdrUEGK1HNQFHyTt4aVpaCTVZcDXQmUheFwfNZmRksaAbBneNm5KyE52SdJeRCN1g6PJmF31GsHWwFiqUDujvasK3wTiDr3vvkYwEJHt7H5RGEKYEp1ErtQtcEBgsgY2DA9JZkHj1J9HZ8MRDTguAhoFtR4aTBQhgnkP4SwVbxDYMEZoF2TMYn3s#zUC7LTa4hWtaE9YKyDsMVGiRNqPMN3s4rjBdB3MFi6PcVWReNfR72y3oGW2NhNcaKNVhMobh7aHp8oZB3qdJCs7RebM2xsodrSm8MmePbN25NTGcpjkJMwKbcWfYDX7eHCJjPGM"
  },
  "id":"http://example.gov/credentials/3732",
  "issuanceDate":"2020-03-10T04:24:12.164Z",
  "issuer":"did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2",
  "type":[
    "VerifiableCredential"
  ]
}`

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) { return m(req) }

func TestClient_Witness(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/.well-known/webfinger" {
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

		const endpoint = "https://example.com"
		client := New(endpoint, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
			WithDocumentLoader(testutil.GetLoader(t)), WithAuthWriteToken("write"),
			WithAuthReadToken("read"))

		resp, err := client.Witness([]byte(mockVC))
		require.NoError(t, err)

		var p Proof
		require.NoError(t, json.Unmarshal(resp, &p))

		require.Len(t, p.Context, 1)
		timestampTime, err := time.Parse(time.RFC3339, p.Proof["created"].(string))
		require.NoError(t, err)

		require.Equal(t, int64(1627462750739000000), timestampTime.UnixNano())
	})
	t.Run("Success (no vct)", func(t *testing.T) {
		client := New("", &mockSigner{}, &mocks.MetricsProvider{}, WithDocumentLoader(testutil.GetLoader(t)))

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
		client := New("", &mockSigner{}, &mocks.MetricsProvider{})

		_, err := client.Witness([]byte(`[]`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse credential")
	})
	t.Run("Bad signature", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/.well-known/webfinger" {
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

		const endpoint = "https://example.com"
		client := New(endpoint, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
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

		const endpoint = "https://example.com"
		client := New(endpoint, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
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

		const endpoint = "https://example.com"
		client := New(endpoint, &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP),
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

		client := New("https://example.com", &mockSigner{}, &mocks.MetricsProvider{},
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

		client := New("https://example.com", &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

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

		client := New("https://example.com", &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

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

		client := New("https://example.com", &mockSigner{}, &mocks.MetricsProvider{}, WithHTTPClient(mockHTTP))

		err := client.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct error")
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
