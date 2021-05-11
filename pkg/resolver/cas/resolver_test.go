/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	casresolver "github.com/trustbloc/orb/pkg/resolver/cas"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

const sampleData = `{
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

const sampleDataCID = "QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ"

func TestNew(t *testing.T) {
	createNewResolver(t, createInMemoryCAS(t))
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Run("No need to get data from remote since it was passed in", func(t *testing.T) {
			resolver := createNewResolver(t, createInMemoryCAS(t))

			id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCID))
			require.NoError(t, err)

			data, err := resolver.Resolve(id, sampleDataCID,
				[]byte(sampleData))
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
		t.Run("No need to get data from remote since it was found locally", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			resolver := createNewResolver(t, casClient)

			id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", cid))
			require.NoError(t, err)

			println(id.String())

			data, err := resolver.Resolve(id, cid, nil)
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
		t.Run("Had to retrieve from remote server", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			webCAS := webcas.New(casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc(webCAS.Path(), webCAS.Handler())

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
			// for it.
			resolver := createNewResolver(t, createInMemoryCAS(t))

			id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, cid))
			require.NoError(t, err)

			data, err := resolver.Resolve(id, cid, nil)
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
	})
	t.Run("CID doesn't match the provided data", func(t *testing.T) {
		resolver := createNewResolver(t, createInMemoryCAS(t))

		cid := "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", cid))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, cid, []byte(sampleData))
		require.EqualError(t, err, "failure while storing the data in the local CAS: "+
			"successfully stored data into the local CAS, but the CID produced by the local CAS "+
			"(QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ) does not match the CID from the original request "+
			"(bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy)")
		require.Nil(t, data)
	})
	t.Run("Neither local nor remote CAS has the data", func(t *testing.T) {
		webCAS := webcas.New(createInMemoryCAS(t))
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test. Its CAS won't have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it. The remote Orb server's CAS also won't have the data we need.
		resolver := createNewResolver(t, createInMemoryCAS(t))

		id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, sampleDataCID))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while getting and storing data from the remote "+
			"WebCAS endpoint: failed to retrieve data from")
		require.Contains(t, err.Error(), "Response status code: 404. Response body: "+
			"no content at QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ was found: content not found")
		require.Nil(t, data)
	})
	t.Run("Fail to write to local CAS", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		cid, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		webCAS := webcas.New(casClient)
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		failingCASClient, err := cas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrGet: ariesstorage.ErrDataNotFound,
				ErrPut: errors.New("put error"),
			},
		})
		require.NoError(t, err)

		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it.
		resolver := createNewResolver(t, failingCASClient)

		id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, cid))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, cid, nil)
		require.EqualError(t, err, "failure while getting and storing data from the remote WebCAS endpoint: "+
			"failure while storing data retrieved from the remote WebCAS endpoint locally: "+
			"failed to write data to CAS (and calculate CID in the process of doing so): "+
			"failed to put content into underlying storage provider: put error")
		require.Nil(t, data)
	})
	t.Run("Other failure when reading from local CAS", func(t *testing.T) {
		casClient, err := cas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrGet: errors.New("get error"),
			},
		})
		require.NoError(t, err)

		resolver := createNewResolver(t, casClient)

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCID))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCID, nil)
		require.EqualError(t, err, "failed to get data stored at "+
			"QmRQB1fQpB4ahvV1fsbjE3fKkT4U9oPjinRofjgS3B9ZEQ from the local CAS: "+
			"failed to get content from the underlying storage provider: get error")
		require.Nil(t, data)
	})
	t.Run("Fail to execute GET call", func(t *testing.T) {
		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it.
		resolver := createNewResolver(t, createInMemoryCAS(t))

		id, err := url.Parse("InvalidWebCASEndpoint")
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCID, nil)
		require.EqualError(t, err, "failure while getting and storing data from the remote WebCAS endpoint: "+
			"failed to execute GET call on InvalidWebCASEndpoint: Get "+
			`"InvalidWebCASEndpoint": unsupported protocol scheme ""`)
		require.Nil(t, data)
	})
}

func createNewResolver(t *testing.T, casClient casapi.Client) *casresolver.Resolver {
	t.Helper()

	casResolver := casresolver.New(casClient, &http.Client{})
	require.NotNil(t, casResolver)

	return casResolver
}

func createInMemoryCAS(t *testing.T) casapi.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider())
	require.NoError(t, err)

	return casClient
}
