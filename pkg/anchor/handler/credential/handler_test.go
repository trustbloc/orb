/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

//go:generate counterfeiter -o ../../mocks/anchorPublisher.gen.go --fake-name AnchorPublisher . anchorPublisher

//nolint:lll
const sampleAnchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "anchors": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "ID": "did:orb:uAAA:EiAqm7CXVPxriNZv_A6GVCrqlmCmrUSGJ1YaheTzFxa_Fw"
            }
          ]
        },
        "subject": "hl:uEiDYMTm9nJ5B0gwpNtflwrcZCT9uT6BFiEs5sYWB45piXg:uoQ-BeEJpcGZzOi8vYmFma3JlaWd5Z2U0MzNoZTZpaGpheWtqdzI3czRmbnl6YmU3dzR0NWFpd2Vld29ucnF3YTZoZ3RjbHk"
      },
      "generator": "https://w3id.org/orb#v0",
      "tag": [
        {
          "type": "Link",
          "href": "hl:uEiDzOEQi2wRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
          "rel": [
            "witness"
          ]
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw"
    },
    {
      "contentObject": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/security/jws/v1"
        ],
        "credentialSubject": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
        "id": "http://orb2.domain1.com/vc/3994cc26-555c-47f1-9890-058148c154f1",
        "issuanceDate": "2021-10-14T18:32:17.894314751Z",
        "issuer": "http://orb2.domain1.com",
        "proof": [
          {
            "created": "2021-10-14T18:32:17.91Z",
            "domain": "http://orb.vct:8077/maple2020",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..h3-0HC3L87TM0j0o3Nd0VLlalcVVphwOPsfdkCLZ4q-uL4z8eO2vQ4sobbtOtFpNNZlpIOQnaWJMX3Ch5Wh-AQ",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain1.com#orb1key"
          },
          {
            "created": "2021-10-14T18:32:18.09110265Z",
            "domain": "https://orb.domain2.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DSL3zsltnh9dbSn3VNPb1C-6pKt6VOy-H1WadO5ZV2QZd3xZq3uRRhaShi9K1SzX-VaGPxs3gfbazJ-fpHVxBg",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain2.com#orb2key"
          }
        ],
        "type": "VerifiableCredential"
      },
      "generator": "https://w3id.org/orb#v0",
      "type": "AnchorObject",
      "url": "hl:uEiDzOEQi2wRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw"
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "published": "2021-10-14T18:32:17.888176489Z",
  "type": "AnchorEvent",
  "url": "hl:uEiDhdDIS_-_SWKoh5Y3KJ_sWpIoXZUPBeTBMCSBUKXpe5w:uoQ-BeEJpcGZzOi8vYmFma3JlaWhib3F6YmY3N3Ayam1rdWlwZnJ4ZmNwNnl3dXNmYm96a2R5ZjR0YXRhamVia2NzNnM2NDQ"
}`

func TestNew(t *testing.T) {
	newAnchorEventHandler(t, createInMemoryCAS(t))
}

func TestAnchorCredentialHandler(t *testing.T) {
	actor := testutil.MustParseURL("https://domain1.com/services/orb")

	t.Run("Success - embedded anchor event", func(t *testing.T) {
		handler := newAnchorEventHandler(t, createInMemoryCAS(t))

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(sampleAnchorEvent), anchorEvent))

		hl, err := hashlink.New().CreateHashLink([]byte(testutil.GetCanonical(t, sampleAnchorEvent)), nil)
		require.NoError(t, err)

		err = handler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), anchorEvent)
		require.NoError(t, err)
	})

	t.Run("Success - no embedded anchor event", func(t *testing.T) {
		casStore := createInMemoryCAS(t)

		hl, err := casStore.Write([]byte(testutil.GetCanonical(t, sampleAnchorEvent)))
		require.NoError(t, err)

		handler := newAnchorEventHandler(t, casStore)

		err = handler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil)
		require.NoError(t, err)
	})

	t.Run("Parse created time (error)", func(t *testing.T) {
		cred := strings.Replace(sampleAnchorEvent, "2021-10-14T18:32:17.91Z", "2021-27T09:30:00Z", 1)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(cred), anchorEvent))

		hl, err := hashlink.New().CreateHashLink([]byte(testutil.GetCanonical(t, cred)), nil)
		require.NoError(t, err)

		err = newAnchorEventHandler(t, createInMemoryCAS(t)).
			HandleAnchorEvent(actor, testutil.MustParseURL(hl), anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse created: parsing time")
	})

	t.Run("Ignore time and domain", func(t *testing.T) {
		cred := strings.Replace(strings.Replace(
			sampleAnchorEvent, `"2021-01-27T09:30:00Z"`, "null", 1,
		), `"https://witness1.example.com/ledgers/maple2021"`, "null", 1)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(cred), anchorEvent))

		hl, err := hashlink.New().CreateHashLink([]byte(testutil.GetCanonical(t, cred)), nil)
		require.NoError(t, err)

		require.NoError(t, newAnchorEventHandler(t, createInMemoryCAS(t)).
			HandleAnchorEvent(actor, testutil.MustParseURL(hl), anchorEvent))
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
		anchorCredentialHandler := newAnchorEventHandler(t, createInMemoryCAS(t))

		hl, err := hashlink.New().CreateHashLink([]byte(sampleAnchorEvent), nil)
		require.NoError(t, err)

		err = anchorCredentialHandler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "content not found")
	})
}

func newAnchorEventHandler(t *testing.T,
	client extendedcasclient.Client) *AnchorEventHandler {
	t.Helper()

	casResolver := casresolver.New(client, nil,
		casresolver.NewWebCASResolver(
			transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			webfingerclient.New(), "https"),
		&orbmocks.MetricsProvider{})

	anchorCredentialHandler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
		&mocks.MonitoringService{}, time.Second)
	require.NotNil(t, anchorCredentialHandler)

	return anchorCredentialHandler
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider(), "https://domain.com/cas", nil, &orbmocks.MetricsProvider{}, 0)

	require.NoError(t, err)

	return casClient
}
