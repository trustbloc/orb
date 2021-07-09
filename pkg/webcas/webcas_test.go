/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas_test

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

const sampleAnchorCredential = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1",
    "https://w3id.org/security/jws/v1"
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
  "proof": [{
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:00Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "sally.example.com",
    "jws": "eyJ..."
  },
  {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:05Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "https://witness1.example.com/ledgers/maple2021",
    "jws": "eyJ..."
  },
  {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:06Z",
    "verificationMethod": "did:example:efgh#key",
    "domain": "https://witness2.example.com/ledgers/spruce2021",
    "jws": "eyJ..."
  }]                  
}`

func TestNew(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), nil)
	require.NoError(t, err)

	webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
	require.NotNil(t, webCAS)
	require.Equal(t, "/cas/{cid}", webCAS.Path())
	require.Equal(t, http.MethodGet, webCAS.Method())
	require.NotNil(t, webCAS.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("Content found", func(t *testing.T) {
		casClient, err := cas.New(mem.NewProvider(), nil)
		require.NoError(t, err)

		cid, err := casClient.Write([]byte(sampleAnchorCredential))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
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
		require.Equal(t, sampleAnchorCredential, string(responseBody))
	})
	t.Run("Content not found", func(t *testing.T) {
		casClient, err := cas.New(mem.NewProvider(), nil)
		require.NoError(t, err)

		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
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

	t.Run("Authorization", func(t *testing.T) {
		casClient, err := cas.New(mem.NewProvider(), nil)
		require.NoError(t, err)

		cfg := &resthandler.Config{
			Config: auth.Config{
				AuthTokensDef: []*auth.TokenDef{
					{
						EndpointExpression: "/cas",
						ReadTokens:         []string{"read"},
					},
				},
				AuthTokens: map[string]string{
					"read": "READ_TOKEN",
				},
			},
		}

		t.Run("Authorized", func(t *testing.T) {
			actor := testutil.MustParseURL("https://sally.example.com/services/orb")

			v := &mocks.SignatureVerifier{}
			v.VerifyRequestReturns(true, actor, nil)

			webCAS := webcas.New(cfg, memstore.New(""), v, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc(webCAS.Path(), webCAS.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/cas/QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG")
			require.NoError(t, err)

			require.Equal(t, http.StatusNotFound, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})

		t.Run("Unauthorized", func(t *testing.T) {
			webCAS := webcas.New(cfg, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc(webCAS.Path(), webCAS.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/cas/QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG")
			require.NoError(t, err)

			require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})

		t.Run("Authorization error", func(t *testing.T) {
			sigVerifier := &mocks.SignatureVerifier{}
			sigVerifier.VerifyRequestReturns(false, nil, errors.New("injected authorization error"))

			webCAS := webcas.New(cfg, memstore.New(""), sigVerifier, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc(webCAS.Path(), webCAS.Handler())

			testServer := httptest.NewServer(router)
			defer testServer.Close()

			response, err := http.DefaultClient.Get(testServer.URL + "/cas/QmeKWPxUJP9M3WJgBuj8ykLtGU37iqur5gZ8cDCi49WJVG")
			require.NoError(t, err)

			require.Equal(t, http.StatusInternalServerError, response.StatusCode)
			require.NoError(t, response.Body.Close())
		})
	})
}
