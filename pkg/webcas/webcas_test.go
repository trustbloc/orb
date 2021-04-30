/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

const sampleContent = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1",
    "https://w3id.org/jws/v1"
  ],
  "id": "http://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ],
  "issuer": "https://sally.example.com/services/orb",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
    "operationCount": 1,
    "coreIndex": "bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "namespace": "did:orb",
    "version": "1",
    "previousAnchors": {
      "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrmenuxhgaomod4m26ds5ztdujxzhjobgvpsyl2v2ndcskq2iay",
      "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3whnisud76knkv7z7ucbf3k2rs6knhvajernrdabdbfaomakli"
    },
    "type": "Anchor"
  },
  "proof": [{}]                  
}`

func TestNew(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider())
	require.NoError(t, err)

	webCAS := webcas.New(casClient)
	require.NotNil(t, webCAS)
	require.Equal(t, "/cas/{cid}", webCAS.Path())
	require.Equal(t, http.MethodGet, webCAS.Method())
	require.NotNil(t, webCAS.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("Content found", func(t *testing.T) {
		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		cid, err := casClient.Write([]byte(sampleContent))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		webCAS := webcas.New(casClient)
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/cas/" + cid)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, sampleContent, string(responseBody))
	})
	t.Run("Content not found", func(t *testing.T) {
		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		webCAS := webcas.New(casClient)
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/cas/QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		responseBody, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusNotFound, response.StatusCode)
		require.Equal(t, "no content at QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG was found: "+
			"content not found", string(responseBody))
	})
}
