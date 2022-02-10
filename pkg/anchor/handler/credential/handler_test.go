/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	mocks2 "github.com/trustbloc/orb/pkg/protocolversion/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
	"github.com/trustbloc/orb/pkg/webcas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

//go:generate counterfeiter -o ../../mocks/anchorPublisher.gen.go --fake-name AnchorPublisher . anchorPublisher

func TestNew(t *testing.T) {
	newAnchorEventHandler(t, createInMemoryCAS(t))
}

func TestAnchorCredentialHandler(t *testing.T) {
	log.SetLevel("anchor-credential-handler", log.DEBUG)

	actor := testutil.MustParseURL("https://domain1.com/services/orb")

	t.Run("Success - embedded anchor event", func(t *testing.T) {
		handler := newAnchorEventHandler(t, createInMemoryCAS(t))

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(sampleAnchorEvent), anchorEvent))

		hl, err := hashlink.New().CreateHashLink([]byte(testutil.GetCanonical(t, sampleAnchorEvent)), nil)
		require.NoError(t, err)

		err = handler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), actor, anchorEvent)
		require.NoError(t, err)
	})

	t.Run("Success - no embedded anchor event", func(t *testing.T) {
		casStore := createInMemoryCAS(t)

		hl, err := casStore.Write([]byte(testutil.GetCanonical(t, sampleAnchorEvent)))
		require.NoError(t, err)

		handler := newAnchorEventHandler(t, casStore)

		err = handler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, nil)
		require.NoError(t, err)
	})

	t.Run("Parse created time (error)", func(t *testing.T) {
		cred := strings.Replace(sampleAnchorEvent, "2022-02-10T18:50:48.682348236Z", "2021-27T09:30:00Z", 1)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(cred), anchorEvent))

		hl, err := hashlink.New().CreateHashLink([]byte(testutil.GetCanonical(t, cred)), nil)
		require.NoError(t, err)

		err = newAnchorEventHandler(t, createInMemoryCAS(t)).
			HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, anchorEvent)
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
			HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, anchorEvent))
	})

	t.Run("Neither local nor remote CAS has the anchor credential", func(t *testing.T) {
		webCAS := webcas.New(&resthandler.Config{}, memstore.New(""), &servicemocks.SignatureVerifier{},
			createInMemoryCAS(t), &apmocks.AuthTokenMgr{})
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

		err = anchorCredentialHandler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "content not found")
	})
}

func TestGetUnprocessedParentAnchorEvents(t *testing.T) {
	const (
		parentHL      = "hl:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ1FocExjamhPVl90RFZpYlVmUGJraGpKTV9GVVl3UTlBdUFIYWhvQUd4eWc" //nolint:lll
		grandparentHL = "hl:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ1FocExjamhPVl90RFZpYlVmUGJraGpKTV9GVVl3UTlBdUFIYWhvQUd4eWc" //nolint:lll
	)

	t.Run("All parents processed -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorEvent), anchorEvent))

		anchorLinkStore.GetLinksReturns([]*url.URL{vocab.MustParseURL(grandparentHL)}, nil)

		parents, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.NoError(t, err)
		require.Empty(t, parents)
	})

	t.Run("One parent unprocessed -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorEvent), anchorEvent))

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturns([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorEvent)), grandparentHL, nil)

		parents, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.NoError(t, err)
		require.Len(t, parents, 1)
	})

	t.Run("Duplicate parents -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithParent(vocab.MustParseURL(grandparentHL), vocab.MustParseURL(grandparentHL)),
		)

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturns([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorEvent)), grandparentHL, nil)

		parents, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.NoError(t, err)
		require.Len(t, parents, 1)
	})

	t.Run("Unmarshal -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		errExpected := errors.New("injected unmarshal error")

		handler.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorEvent), anchorEvent))

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturns([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorEvent)), grandparentHL, nil)

		_, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Invalid parent hashlink -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := vocab.NewAnchorEvent(vocab.WithParent(vocab.MustParseURL("udp://invalid")))

		anchorLinkStore.GetLinksReturns(nil, nil)

		_, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must start with 'hl:' prefix")
	})

	t.Run("GetLinks -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := vocab.NewAnchorEvent(vocab.WithParent(vocab.MustParseURL(grandparentHL)))

		errExpected := errors.New("injected GetLinks error")

		anchorLinkStore.GetLinksReturns(nil, errExpected)

		_, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("CAS Resolver -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			&mocks.MonitoringService{}, time.Second, anchorLinkStore)
		require.NotNil(t, handler)

		anchorEvent := vocab.NewAnchorEvent(vocab.WithParent(vocab.MustParseURL(grandparentHL)))

		errExpected := errors.New("injected Resolve error")

		casResolver.ResolveReturns(nil, "", errExpected)

		_, err := handler.getUnprocessedParentAnchorEvents(parentHL, anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func newAnchorEventHandler(t *testing.T,
	client extendedcasclient.Client) *AnchorEventHandler {
	t.Helper()

	casResolver := casresolver.New(client, nil,
		casresolver.NewWebCASResolver(
			transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
			webfingerclient.New(), "https"),
		&orbmocks.MetricsProvider{})

	anchorLinkStore := &orbmocks.AnchorLinkStore{}

	anchorEventHandler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
		&mocks.MonitoringService{}, time.Second, anchorLinkStore)
	require.NotNil(t, anchorEventHandler)

	return anchorEventHandler
}

func createInMemoryCAS(t *testing.T) extendedcasclient.Client {
	t.Helper()

	casClient, err := cas.New(mem.NewProvider(), "https://orb.domain1.com/cas", nil,
		&orbmocks.MetricsProvider{}, 0)
	require.NoError(t, err)

	resourceHash, err := casClient.Write([]byte(testutil.GetCanonical(t, sampleParentAnchorEvent)))
	require.NoError(t, err)

	t.Logf("Stored parent anchor: %s", resourceHash)

	resourceHash, err = casClient.Write([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorEvent)))
	require.NoError(t, err)

	t.Logf("Stored grandparent anchor: %s", resourceHash)

	return casClient
}

//nolint:lll
const sampleAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:EiCIZ19PGWe_65JLcIp_bmOu_ZrPOerFPXAoXAcdWW7iCg\",\"previousAnchor\":\"hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw\"}]},\"subject\":\"hl:uEiC0arCOQrIDw2F2Zca10gEutIrHWgIUaC1jPDRRBLADUQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQzBhckNPUXJJRHcyRjJaY2ExMGdFdXRJckhXZ0lVYUMxalBEUlJCTEFEVVE\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA\",\"id\":\"https://orb.domain2.com/vc/1636951e-9117-4134-904a-e0cd177517a1\",\"issuanceDate\":\"2022-02-10T18:50:48.682168399Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T18:50:48.682348236Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fqgLBKohg962_3GNbH-QXklA89KBMHev95-Pk1XcGa47jq0TbFUeZi3DBGLgc-pDBisqkh0U3bUSvKY_edBAAw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T18:50:48.729Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..xlI19T5KT-Sy1CJuCQLIhgGHdlaK0dIjoctRwzJUz6-TpiluluGEa69aCuDjx426TgHvGXJDn8jHi5aDqGuTDA\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA",
  "parent": "hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWswQ1V1SUlWT3hsYWxZSDZKVTdnc0l3dm81ekdOY01fellvMmpYd3pCenc",
  "published": "2022-02-10T18:50:48.681998572Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const sampleParentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:EiCIZ19PGWe_65JLcIp_bmOu_ZrPOerFPXAoXAcdWW7iCg\",\"previousAnchor\":\"hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw\"}]},\"subject\":\"hl:uEiC0arCOQrIDw2F2Zca10gEutIrHWgIUaC1jPDRRBLADUQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQzBhckNPUXJJRHcyRjJaY2ExMGdFdXRJckhXZ0lVYUMxalBEUlJCTEFEVVE\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA\",\"id\":\"https://orb.domain2.com/vc/1636951e-9117-4134-904a-e0cd177517a1\",\"issuanceDate\":\"2022-02-10T18:50:48.682168399Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T18:50:48.682348236Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fqgLBKohg962_3GNbH-QXklA89KBMHev95-Pk1XcGa47jq0TbFUeZi3DBGLgc-pDBisqkh0U3bUSvKY_edBAAw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T18:50:48.729Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..xlI19T5KT-Sy1CJuCQLIhgGHdlaK0dIjoctRwzJUz6-TpiluluGEa69aCuDjx426TgHvGXJDn8jHi5aDqGuTDA\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA",
  "parent": "hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWswQ1V1SUlWT3hsYWxZSDZKVTdnc0l3dm81ekdOY01fellvMmpYd3pCenc",
  "published": "2022-02-10T18:50:48.681998572Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const sampleGrandparentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uAAA:EiCIZ19PGWe_65JLcIp_bmOu_ZrPOerFPXAoXAcdWW7iCg\"}]},\"subject\":\"hl:uEiB_EO3wonWIqC-2qzI730l3IQhYCzNxWtdNynBJi_O-uw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQl9FTzN3b25XSXFDLTJxekk3MzBsM0lRaFlDek54V3RkTnluQkppX08tdXc\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiB-dxzjTbnnyxGyLYFqZof9YahIFO-JHR-u6pZIcbFiAg",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiBOxwW4jVeoEXk-D2GK1rVfLDxqiKBNK1aPxhtDq-4WUw"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiBOxwW4jVeoEXk-D2GK1rVfLDxqiKBNK1aPxhtDq-4WUw\",\"id\":\"https://orb.domain2.com/vc/525b6a6d-b288-47ed-bf5f-1cc7a5c161f1\",\"issuanceDate\":\"2022-02-10T18:50:45.695225137Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T18:50:45.695532436Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..uWopymt6qTIyXFAN3cETf7XXkTCcqSNA7Cqw9GALcq-Ax19tjAMpcAT_VPoM3Kf-RUb8s5lDgsozMCwWXakZBg\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T18:50:45.784Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..61LDooN6Lg71-YX3R371O9z7m15M2iG30QBDxNDWG3psg50HXiA7JJOn245nBaV9_pee_lzB0kjBD1CYg7Y_BQ\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiB-dxzjTbnnyxGyLYFqZof9YahIFO-JHR-u6pZIcbFiAg"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiBOxwW4jVeoEXk-D2GK1rVfLDxqiKBNK1aPxhtDq-4WUw",
  "published": "2022-02-10T18:50:45.692283508Z",
  "type": "AnchorEvent"
}`
