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
	"time"

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
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
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
	httpScheme      = "http"
	sampleCASURL    = "http://domain.com/cas"
)

func TestNew(t *testing.T) {
	createNewResolver(t, createInMemoryCAS(t), createInMemoryCAS(t))
}

func TestResolver_Resolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Run("No need to get data from remote since it was passed in", func(t *testing.T) {
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)

			t.Run("v1", func(t *testing.T) {
				rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
				require.NoError(t, err)

				data, err := resolver.Resolve(nil, rh,
					[]byte(sampleData))
				require.NoError(t, err)
				require.Equal(t, string(data), sampleData)
			})
		})
		t.Run("No need to get data from remote since it was found locally", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

			resolver := createNewResolver(t, casClient, nil)

			rh, err := hashlink.GetResourceHashFromHashLink(hl)
			require.NoError(t, err)

			id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", rh))
			require.NoError(t, err)

			println(id.String())

			data, err := resolver.Resolve(id, hl, nil)
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
		t.Run("Had to retrieve from remote server", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

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

			rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
			require.NoError(t, err)

			md, err := hashlink.New().CreateMetadataFromLinks([]string{fmt.Sprintf("%s/cas/%s", testServer.URL, rh)})
			require.NoError(t, err)

			hl = hashlink.GetHashLink(rh, md)

			data, err := resolver.Resolve(nil, hl, nil)
			require.NoError(t, err)
			require.Equal(t, string(data), sampleData)
		})
	})
	t.Run("Had to retrieve data from second remote server", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		hl, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

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

		rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
		require.NoError(t, err)

		links := []string{"https://localhost:9090/cas", fmt.Sprintf("%s/cas/%s", testServer.URL, rh)}

		md, err := hashlink.New().CreateMetadataFromLinks(links)
		require.NoError(t, err)

		hl = hashlink.GetHashLink(rh, md)

		data, err := resolver.Resolve(nil, hl, nil)
		require.NoError(t, err)
		require.Equal(t, string(data), sampleData)
	})

	t.Run("Had to retrieve data from remote server via hint", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		hl, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		rh, err := hashlink.GetResourceHashFromHashLink(hl)
		require.NoError(t, err)

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

		hashWithHint := "https:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + rh

		// The local resolver here has a CAS without the data we need,
		// so it'll have to ask the remote Orb server for it.
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)
		resolver.webCASResolver.webFingerURIScheme = httpScheme

		data, err := resolver.Resolve(nil, hashWithHint, nil)
		require.NoError(t, err)
		require.Equal(t, sampleData, string(data))
	})

	t.Run("Had to retrieve data from remote server via hint (not found)", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		hl, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		rh, err := hashlink.GetResourceHashFromHashLink(hl)
		require.NoError(t, err)

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

		hashWithHint := "https:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + rh

		resolver := createNewResolver(t, createInMemoryCAS(t), nil)
		resolver.webCASResolver.webFingerURIScheme = httpScheme

		data, err := resolver.Resolve(nil, hashWithHint, nil)
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "Response status code: 404")
	})

	t.Run("Had to retrieve data from ipfs via hashlink hint", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, sampleData)
		}))
		defer ipfsServer.Close()

		hl, err := hashlink.New().CreateHashLink([]byte(sampleData), []string{"ipfs://" + sampleDataCIDv1})
		require.NoError(t, err)

		ipfsClient := ipfs.New(ipfsServer.URL, 5*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, ipfsClient)

		resolver := createNewResolver(t, createInMemoryCAS(t), ipfsClient)

		data, err := resolver.Resolve(nil, hl, nil)
		require.NoError(t, err)
		require.Equal(t, string(data), sampleData)
	})

	t.Run("error - failed to retrieve data from two servers", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
		require.NotNil(t, webCAS)

		router := mux.NewRouter()

		router.HandleFunc(webCAS.Path(), webCAS.Handler())

		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it.
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
		require.NoError(t, err)

		links := []string{"https://localhost:9090/cas", "https://localhost:9091/cas"}

		md, err := hashlink.New().CreateMetadataFromLinks(links)
		require.NoError(t, err)

		hl := hashlink.GetHashLink(rh, md)

		data, err := resolver.Resolve(nil, hl, nil)
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "https://localhost:9090/cas")
		require.Contains(t, err.Error(), "https://localhost:9091/cas")
	})

	t.Run("error - hint not supported", func(t *testing.T) {
		ipfsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, sampleData)
		}))
		defer ipfsServer.Close()

		ipfsClient := ipfs.New(ipfsServer.URL, 5*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, ipfsClient)

		resolver := createNewResolver(t, createInMemoryCAS(t), ipfsClient)

		data, err := resolver.Resolve(nil, "invalid:"+sampleDataCIDv1, nil)
		require.Error(t, err)
		require.Empty(t, data)
		require.Contains(t, err.Error(), "hint 'invalid' not supported")
	})

	t.Run("error - invalid hash link", func(t *testing.T) {
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		data, err := resolver.Resolve(nil, "hl:abc", nil)
		require.Error(t, err)
		require.Empty(t, data)
		require.Contains(t, err.Error(), "resource hash[abc] for hashlink[hl:abc] is not a valid multihash")
	})

	t.Run("CID doesn't match the provided data", func(t *testing.T) {
		resolver := createNewResolver(t, createInMemoryCAS(t), nil)

		cid := "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy" // Not a match

		data, err := resolver.Resolve(nil, cid, []byte(sampleData))
		require.EqualError(t, err, "failed to store the data in the local CAS: "+
			"successfully stored data into the local CAS, but the resource hash produced by the local CAS "+
			"(uEiA1t3VICW2jRlU-m3o7-3f1lI5hbLTrPkefScZMEFwbEQ) does not match the resource hash from the original request "+
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

		rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
		require.NoError(t, err)

		md, err := hashlink.New().CreateMetadataFromLinks([]string{fmt.Sprintf("%s/cas/%s", testServer.URL, rh)})
		require.NoError(t, err)

		hl := hashlink.GetHashLink(rh, md)

		data, err := resolver.Resolve(nil, hl, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while getting and storing data from the remote WebCAS endpoints")
		require.Contains(t, err.Error(), "Response status code: 404. Response body: "+
			"no content at uEiA1t3VICW2jRlU-m3o7-3f1lI5hbLTrPkefScZMEFwbEQ was found: content not found")
		require.Nil(t, data)
	})
	t.Run("Fail to write to local CAS", func(t *testing.T) {
		casClient := createInMemoryCAS(t)

		hl, err := casClient.Write([]byte(sampleData))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

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
		}, sampleCASURL, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		// The local resolver here has a CAS without the data we need, so it'll have to ask the remote Orb server
		// for it.
		resolver := createNewResolver(t, failingCASClient, nil)

		rh, err := hashlink.New().CreateResourceHash([]byte(sampleData))
		require.NoError(t, err)

		md, err := hashlink.New().CreateMetadataFromLinks([]string{fmt.Sprintf("%s/cas/%s", testServer.URL, rh)})
		require.NoError(t, err)

		hl = hashlink.GetHashLink(rh, md)

		data, err := resolver.Resolve(nil, hl, nil)
		require.Contains(t, err.Error(), "failed to put content into underlying storage provider: put error")
		require.True(t, orberrors.IsTransient(err))
		require.Nil(t, data)
	})
	t.Run("Other failure when reading from local CAS", func(t *testing.T) {
		casClient, err := cas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrGet: errors.New("get error"),
			},
		}, sampleCASURL, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		resolver := createNewResolver(t, casClient, nil)

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", sampleDataCIDv1))
		require.NoError(t, err)

		data, err := resolver.Resolve(id, sampleDataCIDv1, nil)
		require.EqualError(t, err, "failed to get data stored at "+
			"bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce from the local CAS: "+
			"failed to get content from the local CAS provider: get error")
		require.True(t, orberrors.IsTransient(err))
		require.Nil(t, data)
	})

	t.Run("fail to determine WebCAS URL via WebFinger", func(t *testing.T) {
		t.Run("non-existent domain", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

			rh, err := hashlink.GetResourceHashFromHashLink(hl)
			require.NoError(t, err)

			hashWithHint := "https:NonExistentDomain:" + rh

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.∂
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webCASResolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, hashWithHint, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to resolve domain and resource hash via WebCAS: "+
				"failed to determine WebCAS URL via WebFinger: "+
				"failed to get WebFinger resource: failed to get response "+
				"(URL: http://NonExistentDomain/.well-known/webfinger?resource=http://Non"+
				`ExistentDomain/cas/uEiA1t3VICW2jRlU-m3o7-3f1lI5hbLTrPkefScZMEFwbEQ): Get "http://`+
				"NonExistentDomain/.well-known/webfinger?resource=http://NonExistentDomain/cas/"+
				`uEiA1t3VICW2jRlU-m3o7-3f1lI5hbLTrPkefScZMEFwbEQ": dial tcp: lookup NonExistentDomain`)
			require.Nil(t, data)
		})

		t.Run("unexpected status code", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

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

			rh, err := hashlink.GetResourceHashFromHashLink(hl)
			require.NoError(t, err)

			hashWithHint := "https:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + rh

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webCASResolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, hashWithHint, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "received unexpected status code")
			require.Nil(t, data)
		})
		t.Run("response isn't a valid WebFinger response object", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
				_, errWrite := rw.Write([]byte("this can't be unmarshalled to a JRD"))
				require.NoError(t, errWrite)
			})

			// This test server is our "remote Orb server" for this test. Its CAS will have the data we need.
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			testServerURI, err := url.Parse(testServer.URL)
			require.NoError(t, err)

			rh, err := hashlink.GetResourceHashFromHashLink(hl)
			require.NoError(t, err)

			cidWithHint := "https:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + rh

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webCASResolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, cidWithHint, nil)
			require.EqualError(t, err, "failed to resolve domain and resource hash via WebCAS: failed to determine "+
				"WebCAS URL via WebFinger: failed to get WebFinger resource: "+
				"failed to unmarshal WebFinger response: invalid character 'h' in "+
				"literal true (expecting 'r')")
			require.Nil(t, data)
		})
		t.Run("WebCAS URL from response can't be parsed as a URL", func(t *testing.T) {
			casClient := createInMemoryCAS(t)

			hl, err := casClient.Write([]byte(sampleData))
			require.NoError(t, err)
			require.NotEmpty(t, hl)

			webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient)
			require.NotNil(t, webCAS)

			router := mux.NewRouter()

			router.HandleFunc("/.well-known/webfinger", func(rw http.ResponseWriter, r *http.Request) {
				webFingerResponse := restapi.JRD{Links: []restapi.Link{
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

			rh, err := hashlink.GetResourceHashFromHashLink(hl)
			require.NoError(t, err)

			hashWithHint := "https:" + testServerURI.Hostname() + ":" + testServerURI.Port() + ":" + rh

			// The local resolver here has a CAS without the data we need,
			// so it'll have to ask the remote Orb server for it.
			resolver := createNewResolver(t, createInMemoryCAS(t), nil)
			resolver.webCASResolver.webFingerURIScheme = httpScheme

			data, err := resolver.Resolve(nil, hashWithHint, nil)
			require.EqualError(t, err, "failed to resolve domain and resource hash via WebCAS: failed to determine "+
				`WebCAS URL via WebFinger: failed to parse webcas URL: parse "%": invalid URL escape "%"`)
			require.Nil(t, data)
		})
	})
}

func createNewResolver(t *testing.T, casClient extendedcasclient.Client, ipfsReader ipfsReader) *Resolver {
	t.Helper()

	webFingerResolver := webfingerclient.New()

	webCASResolver := NewWebCASResolver(
		transport.New(&http.Client{},
			testutil.MustParseURL("https://example.com/keys/public-key"),
			transport.DefaultSigner(), transport.DefaultSigner()),
		webFingerResolver,
		"http")

	casResolver := New(casClient, ipfsReader, webCASResolver, &orbmocks.MetricsProvider{})
	require.NotNil(t, casResolver)

	return casResolver
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	return createInMemoryCASWithLink(t, sampleCASURL)
}

func createInMemoryCASWithLink(t *testing.T, casLink string) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)
	require.NoError(t, err)

	return casClient
}
