/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

const sampleAnchorCredential = `{
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

const sampleAnchorCredentialCID = "QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ"

func TestNew(t *testing.T) {
	createNewAnchorCredentialHandler(t, createInMemoryCAS(t))
}

func TestAnchorCredentialHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		anchorCredentialHandler := createNewAnchorCredentialHandler(t, createInMemoryCAS(t))

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleAnchorCredentialCID))
		require.NoError(t, err)

		err = anchorCredentialHandler.HandleAnchorCredential(id, sampleAnchorCredentialCID,
			[]byte(sampleAnchorCredential))
		require.NoError(t, err)
	})
	t.Run("Neither local nor remote CAS has the anchor credential", func(t *testing.T) {
		webCAS := webcas.New(createInMemoryCAS(t))
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test. Its CAS won't have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		// The local handler here has a resolver configured with a CAS without the data we need, so it'll have to ask
		// the remote Orb server for it. The remote Orb server's CAS also won't have the data we need.
		anchorCredentialHandler := createNewAnchorCredentialHandler(t, createInMemoryCAS(t))

		id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, sampleAnchorCredentialCID))
		require.NoError(t, err)

		err = anchorCredentialHandler.HandleAnchorCredential(id, sampleAnchorCredentialCID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve anchor credential: "+
			"failure while getting and storing data from the remote WebCAS endpoint: "+
			"failed to retrieve data from")
		require.Contains(t, err.Error(), "Response status code: 404. Response body: "+
			"no content at QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ was found: content not found")
	})
}

func createNewAnchorCredentialHandler(t *testing.T, client casapi.Client) *AnchorCredentialHandler {
	t.Helper()

	anchorCh := make(chan []anchorinfo.AnchorInfo, 100)

	casResolver := casresolver.New(client, nil, &http.Client{})

	anchorCredentialHandler := New(anchorCh, casResolver)
	require.NotNil(t, anchorCredentialHandler)

	return anchorCredentialHandler
}

func createInMemoryCAS(t *testing.T) casapi.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider())
	require.NoError(t, err)

	return casClient
}
