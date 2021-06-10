/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"encoding/json"
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

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

const (
	sampleData = `{
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
	sampleDataCIDv1 = "bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce"
	sampleDataCIDv0 = "QmTcU88RwoPzEuLar92g7wiTG9suWwuTwHn6szDBERpzkp"
	httpScheme      = "http"
)

func TestNew(t *testing.T) {
	createNewResolver(t, createInMemoryCAS(t), createInMemoryCAS(t))
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Run("No need to get data from remote since it was passed in", func(t *testing.T) {
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)

			t.Run("v1", func(t *testing.T) {
				id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCIDv1))
				require.NoError(t, err)

				data, err := resolver.Resolve(id, sampleDataCIDv1,
					[]byte(sampleData))
				require.NoError(t, err)
				require.Equal(t, string(data), sampleData)
			})
			t.Run("v0", func(t *testing.T) {
				id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCIDv0))
				require.NoError(t, err)

				data, err := resolver.Resolve(id, sampleDataCIDv0,
					[]byte(sampleData))
				require.NoError(t, err)
				require.Equal(t, string(data), sampleData)
			})
		})
		t.Run("No need to get data from remote since it was found locally", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			resolver := createNewResolver(t, casClient, nil)

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

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc(webCAS.Path(), webCAS.Handler())

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
			// for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)

			id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, cid))
			require.NoError(t, err)

			data, err := resolver.Resolve(id, cid, nil)
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
	})

	t.Run("Had to retrieve data from remote server via hint", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		cid, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		operations, err := restapi.New(&restapi.Config{BaseURL: testServer.URL, WebCASPath: "/cas"})
		require.NoError(t, err)

		router.HandleFunc(operations.GetRESTHandlers()[1].Path(), operations.GetRESTHandlers()[1].Handler())

		testServerURI, err := url.Parse(testServer.URL)
		require.NoError(t, err)

		cidWithHint := "webcas:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + cid

		// The local resolver here has a CAS without the data we need,
		// so it'll have to ask the remote Orb server for it.
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)
		resolver.webFingerURIScheme = httpScheme

		data, err := resolver.Resolve(nil, cidWithHint, nil)
		require.NoError(t, err)
		require.Equal(t, string(data), sampleData)
	})

	t.Run("Had to retrieve data from remote server via hint (not found)", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		cid, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		// remote server doesn't have cid (clean CAS)
		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, createInMemoryCAS(t))
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		operations, err := restapi.New(&restapi.Config{BaseURL: testServer.URL, WebCASPath: "/cas"})
		require.NoError(t, err)

		router.HandleFunc(operations.GetRESTHandlers()[1].Path(), operations.GetRESTHandlers()[1].Handler())

		testServerURI, err := url.Parse(testServer.URL)
		require.NoError(t, err)

		cidWithHint := "webcas:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + cid

		resolver := createNewResolver(t, createInMemoryCAS(t), nil)
		resolver.webFingerURIScheme = httpScheme

		data, err := resolver.Resolve(nil, cidWithHint, nil)
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "Response status code: 404")
	})

	t.Run("Had to retrieve data from ipfs via hint", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, sampleData)
		}))
		defer ipfsServer.Close()

		ipfsClient := ipfs.New(ipfsServer.URL)
		require.NotNil(t, ipfsClient)

		resolver := createNewResolver(t, createInMemoryCAS(t), ipfsClient)

		data, err := resolver.Resolve(nil, "ipfs:"+sampleDataCIDv1, nil)
		require.NoError(t, err)
		require.Equal(t, string(data), sampleData)
	})

	t.Run("Had to retrieve data from ipfs via hint but ipfs client not supported", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, sampleData)
		}))
		defer ipfsServer.Close()

		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		data, err := resolver.Resolve(nil, "ipfs:"+sampleDataCIDv1, nil)
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "ipfs reader is not supported")
	})

	t.Run("Had to retrieve data from ipfs via hint (ipfs error)", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfsServer.Close()

		ipfsClient := ipfs.New(ipfsServer.URL)
		require.NotNil(t, ipfsClient)

		resolver := createNewResolver(t, createInMemoryCAS(t), ipfsClient)

		data, err := resolver.Resolve(nil, "ipfs:"+sampleDataCIDv1, nil)
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "failed to read cid")
	})

	t.Run("Had to retrieve data from ipfs via hint (hint not supported)", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, sampleData)
		}))
		defer ipfsServer.Close()

		ipfsClient := ipfs.New(ipfsServer.URL)
		require.NotNil(t, ipfsClient)

		resolver := createNewResolver(t, createInMemoryCAS(t), ipfsClient)

		data, err := resolver.Resolve(nil, "invalid:"+sampleDataCIDv1, nil)
		require.Error(t, err)
		require.Empty(t, data)
		require.Contains(t, err.Error(), "hint 'invalid' not supported")
	})

	t.Run("CID doesn't match the provided data", func(t *testing.T) {
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		cid := "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy" // Not a match

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", cid))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, cid, []byte(sampleData))
		require.EqualError(t, err, "failure while storing the data in the local CAS: "+
			"successfully stored data into the local CAS, but the CID produced by the local CAS "+
			"(bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce) does not match the CID from the original request "+
			"(bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy)")
		require.Nil(t, data)
	})
	t.Run("Neither local nor remote CAS has the data", func(t *testing.T) {
		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, createInMemoryCAS(t))
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// This test server is our "remote Orb server" for this test. Its CAS won't have the data we need.
		testServer := httptest.NewServer(router)
		defer testServer.Close()

		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it. The remote Orb server's CAS also won't have the data we need.
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		id, err := url.Parse(fmt.Sprintf("%s/cas/%s", testServer.URL, sampleDataCIDv1))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCIDv1, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while getting and storing data from the remote "+
			"WebCAS endpoint: failed to retrieve data from")
		require.Contains(t, err.Error(), "Response status code: 404. Response body: "+
			"no content at bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce was found: content not found")
		require.Nil(t, data)
	})
	t.Run("Fail to write to local CAS", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		cid, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, cid)

		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
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
		resolver := createNewResolver(t, failingCASClient, nil)

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

		resolver := createNewResolver(t, casClient, nil)

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCIDv1))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCIDv1, nil)
		require.EqualError(t, err, "failed to get data stored at "+
			"bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce from the local CAS: "+
			"failed to get content from the underlying storage provider: get error")
		require.Nil(t, data)
	})
	t.Run("Fail to execute GET call", func(t *testing.T) {
		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it.
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		id, err := url.Parse("InvalidWebCASEndpoint")
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCIDv1, nil)
		require.EqualError(t, err, "failure while getting and storing data from the remote WebCAS endpoint: "+
			"failed to execute GET call on InvalidWebCASEndpoint: Get "+
			`"InvalidWebCASEndpoint": unsupported protocol scheme ""`)
		require.Nil(t, data)
	})

	t.Run("fail to determine WebCAS URL via WebFinger", func(t *testing.T) {
		t.Run("non-existent domain", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			cidWithHint := "webcas:NonExistentDomain:" + cid

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.∂
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, cidWithHint, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to determine WebCAS URL via WebFinger: "+
				"failed to get response (URL: http://NonExistentDomain/.well-known/webfinger?resource=http://Non"+
				`ExistentDomain/cas/bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce): Get "http://`+
				"NonExistentDomain/.well-known/webfinger?resource=http://NonExistentDomain/cas/bafkreibvw52uq"+
				`clnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce": dial tcp: lookup NonExistentDomain`)
			require.Nil(t, data)
		})
		t.Run("unexpected status code", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusInternalServerError)
				_, errWrite := rw.Write([]byte("unknown failure"))
				require.NoError(t, errWrite)
			})

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			testServerURI, err := url.Parse(testServer.URL)
			require.NoError(t, err)

			cidWithHint := "webcas:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + cid

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, cidWithHint, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "received unexpected status code")
			require.Nil(t, data)
		})
		t.Run("response isn't a valid WebFinger response object", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
				_, errWrite := rw.Write([]byte("this can't be unmarshalled to a WebFingerResponse"))
				require.NoError(t, errWrite)
			})

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			testServerURI, err := url.Parse(testServer.URL)
			require.NoError(t, err)

			cidWithHint := "webcas:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + cid

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, cidWithHint, nil)
			require.EqualError(t, err, "failed to determine WebCAS URL via WebFinger: "+
				"failed to unmarshal WebFinger response: invalid character 'h' in literal true (expecting 'r')")
			require.Nil(t, data)
		})
		t.Run("WebCAS URL from response can't be parsed as a URL", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			cid, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, cid)

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
				webFingerResponse := restapi.WebFingerResponse{Links: []restapi.WebFingerLink{
					{Rel: "working-copy", Href: "%"},
				}}
				webFingerResponseBytes, errMarshal := json.Marshal(webFingerResponse)
				require.NoError(t, errMarshal)

				_, errWrite := rw.Write(webFingerResponseBytes)
				require.NoError(t, errWrite)
			})

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			testServerURI, err := url.Parse(testServer.URL)
			require.NoError(t, err)

			cidWithHint := "webcas:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + cid

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, cidWithHint, nil)
			require.EqualError(t, err, "failed to determine WebCAS URL via WebFinger: "+
				`failed to parse webcas URL: parse "%": invalid URL escape "%"`)
			require.Nil(t, data)
		})
	})
}

func createNewResolver(t *testing.T, casClient extendedcasclient.Client, ipfsReader ipfsReader) *Resolver {
	t.Helper()

	casResolver := New(casClient, ipfsReader,
		transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
			transport.DefaultSigner(), transport.DefaultSigner()))
	require.NotNil(t, casResolver)

	return casResolver
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider())
	require.NoError(t, err)

	return casClient
}
