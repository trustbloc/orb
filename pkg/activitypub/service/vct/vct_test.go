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

	. "github.com/trustbloc/orb/pkg/activitypub/service/vct"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

// nolint: lll
const mockResponse = `{
   "svct_version":0,
   "id":"bC2kzaBgvf10aYkcnLJaqulTh1a1oLeABtcwosjgDoc=",
   "timestamp":1617977793917,
   "extensions":"",
   "signature":"ewoJCSAgICJhbGdvcml0aG0iOnsKCQkJICAiaGFzaCI6IlNIQTI1NiIsCgkJCSAgInNpZ25hdHVyZSI6IkVDRFNBIiwKCQkJICAidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyIKCQkgICB9LAoJCSAgICJzaWduYXR1cmUiOiJzMGptV3pmK3VDNS9RNU5yNldiWHhDb3FsdE1NS2dJeUV3a05GWEwyd2l2ZS9TbS83OUxRdm50NldrTnZhdVNRWCtVMlc1c0krL0oySlY4WFhzOWYyUT09IgoJCX0="
}`

// nolint: lll
const mockVC = `{
  "@context":[
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
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
  "proof":{
    "created":"2021-02-23T19:36:07Z",
    "nonce":"lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E=",
    "proofPurpose":"assertionMethod",
    "proofValue":"AAwD/6MYBtI1HCCczj4TDhvpwuiDmnTEHwAj9iE1jJ28oqmCNJoVpZY0meC4WKvmrIGznITtEjpjNgfBPOFWuqONxW7YuEpsV+YAOcbWrRgiRi4D3fWGkuSjJRhqVMrPi45a5a9hAtHbXNwhj1I1U0+M5UCLQqZSdySqN8VJQbFUEYJCKAhSoYtbWuOvZ7zOdDU4WAAAAHS13Ue/6efFD+zX8zYGQZoJS8yrrgusVm7D3xjgp/RNoVkc06JwDtpyWBcDd4ub2ZoAAAACQAB6eWN5vGdDdL91hJKXYj0Qhw0OQLNje5Y33twgl+5IzSLOWPE03NDsN+rQAaIQlAZj9fuHwk7p4zV/zMA6noARqnK/X8W+I8t2lkXd99fzlq/ALLE5CMjc8CCX0kLZQ+JUrVOTm+Ui9JloILhpXQAAAAQurv9QZkxw7uwWekPX+uyJxqdAWIYPVErbTqtvVJXWQEr/+IzFxUXDW8IG8b5G4wp0YyARjlepYhRrKBOe4FnZWzNQ4xb+KPhTjMt5r4mIUgMjChQBGUcWrSB6IMlW+5kYGKbTBSRwaLWPnv36KAhOihTYOqQXaSL3oFqfTQKH5Q==",
    "type":"BbsBlsSignatureProof2020",
    "verificationMethod":"did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2"
  },
  "type":[
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ]
}`

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) { return m(req) }

func TestClient_Witness(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/ct/v1/get-public-key" {
				pubKey := `"BMihLNkyUqmi9VOj2TywSsLwuWRNSG3CQNj7elRSunRleSsYT1BQVkKN89hW5auNFZ9v0z0MbHdytWkHARBnz4o="`

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
		client := New(endpoint, &mockSigner{}, WithHTTPClient(mockHTTP))

		resp, err := client.Witness([]byte(mockVC))
		require.NoError(t, err)

		var p Proof
		require.NoError(t, json.Unmarshal(resp, &p))

		require.Len(t, p.Context, 2)
		require.Equal(t, endpoint, p.Proof["domain"])
		timestampTime, err := time.Parse(time.RFC3339, p.Proof["created"].(string))
		require.NoError(t, err)

		require.Equal(t, int64(1617977793917000000), timestampTime.UnixNano())
	})

	t.Run("Bad signature", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/ct/v1/get-public-key" {
				pubKey := `"BMihLNkyUqmi9VOj2TywSsLwuWRNSG3CQNj7elRSunRleSsYT1BQVkKN89hW5auNFZ9v0z0MbHdytWkHARBnz4o="`

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
		client := New(endpoint, &mockSigner{}, WithHTTPClient(mockHTTP))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "verify VC timestamp signature")
	})

	t.Run("Get public key (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New("https://example.com", &mockSigner{}, WithHTTPClient(mockHTTP))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get public key")
	})

	t.Run("Parse credential (error)", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New("https://example.com", &mockSigner{}, WithHTTPClient(mockHTTP))

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

		client := New("https://example.com", &mockSigner{}, WithHTTPClient(mockHTTP))

		_, err := client.Witness([]byte(mockVC))
		require.Error(t, err)
		require.EqualError(t, err, "add VC: error")
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
