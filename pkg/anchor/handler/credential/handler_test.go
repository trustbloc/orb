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
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
)

//go:generate counterfeiter -o ../../mocks/anchorPublisher.gen.go --fake-name AnchorPublisher . anchorPublisher

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

const sampleAnchorCredentialCID = "bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce"

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

	t.Run("Parse created time (error)", func(t *testing.T) {
		const credCID = "bafkreif6crnaygsznb7kk76b2etvgcm2yruvzmquvonuyq6yhahndn6r3q"

		cred := strings.Replace(sampleAnchorCredential, "2021-01-27T09:30:00Z", "2021-27T09:30:00Z", 1)

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", credCID))
		require.NoError(t, err)

		err = createNewAnchorCredentialHandler(t, createInMemoryCAS(t)).HandleAnchorCredential(id, credCID,
			[]byte(cred))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse created: parsing time")
	})

	t.Run("Ignore time and domain", func(t *testing.T) {
		const credCID = "bafkreih2fmnhgefuyd5b4qlq4yzehlei6r2trn56py3f2tfechhhuo4sly"

		cred := strings.Replace(strings.Replace(
			sampleAnchorCredential, `"2021-01-27T09:30:00Z"`, "null", 1,
		), `"https://witness1.example.com/ledgers/maple2021"`, "null", 1)

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", credCID))
		require.NoError(t, err)

		require.NoError(t, createNewAnchorCredentialHandler(t, createInMemoryCAS(t)).HandleAnchorCredential(
			id, credCID, []byte(cred),
		))
	})

	t.Run("Got null credentials", func(t *testing.T) {
		const credCID = "bafkreiduenhjrl7hjgh3lwxr6nvmfv4kzqzzizhzkbydxdabtcjptavzbm"

		id, err := url.Parse(fmt.Sprintf("https://orb.domain1.com/cas/%s", credCID))
		require.NoError(t, err)

		require.NoError(t, createNewAnchorCredentialHandler(t, createInMemoryCAS(t)).HandleAnchorCredential(
			id, credCID, []byte("null"),
		))
	})

	t.Run("Neither local nor remote CAS has the anchor credential", func(t *testing.T) {
		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &apmocks.SignatureVerifier{}, createInMemoryCAS(t))
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
			"no content at bafkreibvw52uqclnundfkpu3pi57w57vsshgc3fu5m7eph2jyzgbaxa3ce was found: content not found")
	})
}

func createNewAnchorCredentialHandler(t *testing.T,
	client extendedcasclient.Client) *AnchorCredentialHandler {
	t.Helper()

	casResolver := casresolver.New(client, nil,
		transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
			transport.DefaultSigner(), transport.DefaultSigner()), "https")

	anchorCredentialHandler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
		&mocks.MonitoringService{}, time.Second)
	require.NotNil(t, anchorCredentialHandler)

	return anchorCredentialHandler
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider(), nil)
	require.NoError(t, err)

	return casClient
}
