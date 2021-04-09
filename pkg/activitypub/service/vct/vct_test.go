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
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/trustbloc/orb/pkg/activitypub/service/vct"
)

// nolint: lll
var mockResponse = `{
   "svct_version":0,
   "id":"bC2kzaBgvf10aYkcnLJaqulTh1a1oLeABtcwosjgDoc=",
   "timestamp":1617794485223,
   "extensions":"",
   "signature":"eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiJkTUVkMDh1U0FSdmhuUmZuN1c1THR6SFdhaHFSWHdNNDZ0OEttaW50VklFZFkvTytNM3dmSjV2WXBIT21Xbm54MUtNMm5rN2krVnc4dGxKL21KNGRiUT09In0="
}`

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) { return m(req) }

func TestClient_Witness(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(mockResponse)),
				StatusCode: http.StatusOK,
			}, nil
		})

		client := New("http://example.com", WithHTTPClient(mockHTTP))

		resp, err := client.Witness(nil)
		require.NoError(t, err)

		var sig *DigitallySigned

		require.NoError(t, json.Unmarshal(resp, &sig))

		require.NotEmpty(t, sig.Signature)
		require.NotEmpty(t, sig.Algorithm.Hash)
		require.NotEmpty(t, sig.Algorithm.Signature)
		require.NotEmpty(t, sig.Algorithm.Type)
	})

	t.Run("Error", func(t *testing.T) {
		mockHTTP := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"message":"error"}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		client := New("http://example.com", WithHTTPClient(mockHTTP))

		_, err := client.Witness(nil)
		require.Error(t, err)
		require.EqualError(t, err, "add VC: error")
	})
}

type DigitallySigned struct {
	Algorithm struct {
		Hash      string `json:"hash"`
		Signature string `json:"signature"`
		Type      string `json:"type"`
	} `json:"algorithm"`
	Signature []byte `json:"signature"`
}
