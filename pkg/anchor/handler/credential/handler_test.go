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
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uAAA:EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
            }
          ]
        },
        "subject": "hl:uEiB1miJeUsG7PiLvFel8DKoluzDVl3OnpjKgAGZS588PXQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWR2dGlyZjR1d2J4bTdjZjN5djVmNmF6a3JmeG15bmxmM3R1NnRkZmlhYW16am9wdHlwbHU"
      },
      "type": "AnchorObject",
      "url": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
      "witness": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "credentialSubject": {
          "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
        },
        "issuanceDate": "2021-01-27T09:30:10Z",
        "issuer": "https://sally.example.com/services/anchor",
        "proof": [
          {
            "created": "2021-01-27T09:30:00Z",
            "domain": "sally.example.com",
            "jws": "eyJ...",
            "proofPurpose": "assertionMethod",
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:example:abcd#key"
          },
          {
            "created": "2021-01-27T09:30:05Z",
            "domain": "https://witness1.example.com/ledgers/maple2021",
            "jws": "eyJ...",
            "proofPurpose": "assertionMethod",
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:example:abcd#key"
          }
        ],
        "type": "VerifiableCredential"
      }
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "published": "2021-01-27T09:30:10Z",
  "type": "AnchorEvent"
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
		cred := strings.Replace(sampleAnchorEvent, "2021-01-27T09:30:00Z", "2021-27T09:30:00Z", 1)

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
