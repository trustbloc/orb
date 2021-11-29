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
		cred := strings.Replace(sampleAnchorEvent, "2021-11-29T15:21:03.074Z", "2021-27T09:30:00Z", 1)

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
				transport.DefaultSigner(), transport.DefaultSigner()),
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
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uEiCPBh27UFpxQq1Sdw-YoyH9n7yPD7AktxAlBGWlMFfGMQ:EiCQNQ4L1bBFtgaFk4FS4kzLyO3gIO15tXn2j0T5EEu2UQ",
              "previousAnchor": "hl:uEiCPBh27UFpxQq1Sdw-YoyH9n7yPD7AktxAlBGWlMFfGMQ"
            },
            {
              "id": "did:orb:uEiCPBh27UFpxQq1Sdw-YoyH9n7yPD7AktxAlBGWlMFfGMQ:EiAN8R3Na3wa_jkqWRHa3GCXlTrVKlXn4UTecMMkjcdAMQ",
              "previousAnchor": "hl:uEiCPBh27UFpxQq1Sdw-YoyH9n7yPD7AktxAlBGWlMFfGMQ"
            }
          ]
        },
        "subject": "hl:uEiB4iWYoR-AfG2-GysgPxs7djSc4zIU08GZu8Y1eEQQDrg:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQjRpV1lvUi1BZkcyLUd5c2dQeHM3ZGpTYzR6SVUwOEdadThZMWVFUVFEcmc"
      },
      "generator": "https://w3id.org/orb#v0",
      "tag": [
        {
          "href": "hl:uEiDqa7j0CTWIUIsndfR1jJwzYdO-31CcUS08e9APyot_-Q",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiBZijGgA16VhYUjoZFUO2ALWjJeuNP1ylWbG1iEQ6ggiQ"
    },
    {
      "contentObject": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "credentialSubject": "hl:uEiBZijGgA16VhYUjoZFUO2ALWjJeuNP1ylWbG1iEQ6ggiQ",
        "id": "https://orb.domain1.com/vc/9c070be5-e08e-4ade-b210-40ea7eb6b3c8",
        "issuanceDate": "2021-11-29T15:21:03.0624724Z",
        "issuer": "https://orb.domain1.com",
        "proof": [
          {
            "created": "2021-11-29T15:21:03.074Z",
            "domain": "http://orb.vct:8077/maple2020",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..q6Qmujh7C6wJFIL0-hajFTpszGOzvd4GasFwXawdUwMa-emLuoVM8qaEBw0C-3GqNWsS0EzgfMTcL-djPte9Dg",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain1.com#orb1key"
          },
          {
            "created": "2021-11-29T15:21:03.1786462Z",
            "domain": "https://orb.domain2.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..q10AkIUmg39QbfiIllvWFVhPVvJeFuCiQzWDdifQ7AdFDmQjchffmTX1MugTYbO5J_dpnZLTfPjXf4XZWIU2AQ",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain2.com#orb2key"
          }
        ],
        "type": "VerifiableCredential"
      },
      "generator": "https://w3id.org/orb#v0",
      "type": "AnchorObject",
      "url": "hl:uEiDqa7j0CTWIUIsndfR1jJwzYdO-31CcUS08e9APyot_-Q"
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "index": "hl:uEiBZijGgA16VhYUjoZFUO2ALWjJeuNP1ylWbG1iEQ6ggiQ",
  "parent": "hl:uEiCPBh27UFpxQq1Sdw-YoyH9n7yPD7AktxAlBGWlMFfGMQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ1BCaDI3VUZweFFxMVNkdy1Zb3lIOW43eVBEN0FrdHhBbEJHV2xNRmZHTVE",
  "published": "2021-11-29T15:21:03.0620444Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const sampleParentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg:EiAN8R3Na3wa_jkqWRHa3GCXlTrVKlXn4UTecMMkjcdAMQ",
              "previousAnchor": "hl:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg"
            },
            {
              "id": "did:orb:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg:EiCQNQ4L1bBFtgaFk4FS4kzLyO3gIO15tXn2j0T5EEu2UQ",
              "previousAnchor": "hl:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg"
            }
          ]
        },
        "subject": "hl:uEiDSfb9B3JJzjHj61vSfM7pYPsl1tKTSTIB9kjEKdQCBWw:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRFNmYjlCM0pKempIajYxdlNmTTdwWVBzbDF0S1RTVElCOWtqRUtkUUNCV3c"
      },
      "generator": "https://w3id.org/orb#v0",
      "tag": [
        {
          "href": "hl:uEiAQZHVlPe0To_t9Mz-K__W6Bf2owOASxjZMdz3EM1akrA",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiDvP1yOfMsF5JYqFH_F4QX12_IOwp9tNRjsRl4fZrofSQ"
    },
    {
      "contentObject": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "credentialSubject": "hl:uEiDvP1yOfMsF5JYqFH_F4QX12_IOwp9tNRjsRl4fZrofSQ",
        "id": "https://orb.domain1.com/vc/ec1c7fc7-7941-4178-ab58-7f0f8e18b8dc",
        "issuanceDate": "2021-11-29T15:20:57.9755326Z",
        "issuer": "https://orb.domain1.com",
        "proof": [
          {
            "created": "2021-11-29T15:20:57.983Z",
            "domain": "http://orb.vct:8077/maple2020",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Hgmb6c6r8RCnJ1Wf7EmhUBoZ73oEoqrb1kETEyNcox27OP1R3fzpq-DoyELbk7fO8to8L241D0bbx9nyzZNAA",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain1.com#orb1key"
          },
          {
            "created": "2021-11-29T15:20:58.0907253Z",
            "domain": "https://orb.domain2.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D5gxR0LGQIsltpKvm4Fwm63xy47ThBP-eJROqxXoEPAwTgMM5_zhGxTK1n_XdEpXg3jtd6VGzzsh86HU50dfBw",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain2.com#orb2key"
          }
        ],
        "type": "VerifiableCredential"
      },
      "generator": "https://w3id.org/orb#v0",
      "type": "AnchorObject",
      "url": "hl:uEiAQZHVlPe0To_t9Mz-K__W6Bf2owOASxjZMdz3EM1akrA"
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "index": "hl:uEiDvP1yOfMsF5JYqFH_F4QX12_IOwp9tNRjsRl4fZrofSQ",
  "parent": "hl:uEiCQhpLcjhOV_tDVibUfPbkhjJM_FUYwQ9AuAHahoAGxyg:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ1FocExjamhPVl90RFZpYlVmUGJraGpKTV9GVVl3UTlBdUFIYWhvQUd4eWc",
  "published": "2021-11-29T15:20:57.975214Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const sampleGrandparentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uAAA:EiAN8R3Na3wa_jkqWRHa3GCXlTrVKlXn4UTecMMkjcdAMQ"
            },
            {
              "id": "did:orb:uAAA:EiCQNQ4L1bBFtgaFk4FS4kzLyO3gIO15tXn2j0T5EEu2UQ"
            }
          ]
        },
        "subject": "hl:uEiCH0q3MEo8iI-tpO-oPYKpAxt_J0CPGZCknwobkmM2d3A:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0gwcTNNRW84aUktdHBPLW9QWUtwQXh0X0owQ1BHWkNrbndvYmttTTJkM0E"
      },
      "generator": "https://w3id.org/orb#v0",
      "tag": [
        {
          "href": "hl:uEiAK350M8UQQlUS6f4hKeWzi5iYvw6n3c96doONIAZe0pQ",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiDvX0mmtBDXE9AswkkfEMOXniSQ_SIbN57Kz8XfV03lUA"
    },
    {
      "contentObject": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "credentialSubject": "hl:uEiDvX0mmtBDXE9AswkkfEMOXniSQ_SIbN57Kz8XfV03lUA",
        "id": "https://orb.domain1.com/vc/433284e4-9891-4bf8-ad01-85de12a15ed8",
        "issuanceDate": "2021-11-29T15:20:55.9382235Z",
        "issuer": "https://orb.domain1.com",
        "proof": [
          {
            "created": "2021-11-29T15:20:55.947Z",
            "domain": "http://orb.vct:8077/maple2020",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..qILZ-0Dk__TbxKYNQJmictTDlCQvPMZK-g9ONCSEz58NYQI3tS4qbyvRrtTWeT84x8Rm4vpb2EDqxQv2pi6cAA",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain1.com#orb1key"
          },
          {
            "created": "2021-11-29T15:20:56.0750857Z",
            "domain": "https://orb.domain2.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..H_OTWQxSx7pypRjGd9q9IOBiDueQO9oJGq0GFZMUQBLLCZYsx5fp1B54yoKHg6_AmwgJOAKgfUIiHuEekcA3BA",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain2.com#orb2key"
          }
        ],
        "type": "VerifiableCredential"
      },
      "generator": "https://w3id.org/orb#v0",
      "type": "AnchorObject",
      "url": "hl:uEiAK350M8UQQlUS6f4hKeWzi5iYvw6n3c96doONIAZe0pQ"
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "index": "hl:uEiDvX0mmtBDXE9AswkkfEMOXniSQ_SIbN57Kz8XfV03lUA",
  "published": "2021-11-29T15:20:55.9326576Z",
  "type": "AnchorEvent"
}`
