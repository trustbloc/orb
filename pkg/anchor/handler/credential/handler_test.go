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
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/info"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
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

	t.Run("Success - embedded anchor Linkset", func(t *testing.T) {
		handler := newAnchorEventHandler(t, createInMemoryCAS(t))

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(sampleGrandparentAnchorEvent), anchorEvent))
		require.NoError(t, handler.HandleAnchorEvent(actor, anchorEvent.URL()[0], actor, anchorEvent))
	})

	t.Run("Success - no embedded anchor Linkset", func(t *testing.T) {
		casStore := createInMemoryCAS(t)

		hl, err := casStore.Write([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorLinkset)))
		require.NoError(t, err)

		handler := newAnchorEventHandler(t, casStore)

		err = handler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, nil)
		require.NoError(t, err)
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

		hl, err := hashlink.New().CreateHashLink([]byte(sampleGrandparentAnchorEvent), nil)
		require.NoError(t, err)

		err = anchorCredentialHandler.HandleAnchorEvent(actor, testutil.MustParseURL(hl), nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "content not found")
	})

	t.Run("Success - embedded anchor Linkset", func(t *testing.T) {
		handler := newAnchorEventHandler(t, createInMemoryCAS(t))

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(sampleGrandparentAnchorEvent), anchorEvent))
		require.NoError(t, handler.HandleAnchorEvent(actor, anchorEvent.URL()[0], actor, anchorEvent))
	})
}

func TestGetUnprocessedParentAnchorEvents(t *testing.T) {
	const (
		hl            = "hl:uEiCZCOxPantSTVJRTndP0yIO9PTgk5pRL1eYHD2R-c_quA:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ1pDT3hQYW50U1RWSlJUbmRQMHlJTzlQVGdrNXBSTDFlWUhEMlItY19xdUF4QmlwZnM6Ly9iYWZrcmVpZXpiZHdlNjJ0M2tqZ3ZldWtvbzVoNWdpcW82dDJvYmU0MmtleHZwZ2E0aHdpN3R0N2t4YQ" //nolint:lll
		parentHL      = "hl:uEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRElSeVp4cE9ZRHRVbFNzcjZ3VS1ZYnQxN1RyQkVxQ25ybFZKc1R0Q2phcGd4QmlwZnM6Ly9iYWZrcmVpZ2lpNHRoZGpoZ2FvMnVzdXZzeDJ5Zmh6cTN3NXBuaGxhcmZpZmh2emt1dG1qM2lrZzJ1eQ" //nolint:lll
		grandparentHL = "hl:uEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRHBVcU54Nnl6X1Zya0RHTWlLZHlkczNRb3RkejN4R1VmSDdQWnBaTnNIZlF4QmlwZnM6Ly9iYWZrcmVpaGpra3J4ZDJ6bTc1bGxzYXl5emNmaG9qM20zdWZjMjV6NTZlbXVwcjdtNnp1d2p3eWhwdQ" //nolint:lll
	)

	registry := generator.NewRegistry()

	t.Run("All parents processed -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorEvent), anchorEvent))

		anchorLinkStore.GetLinksReturns([]*url.URL{vocab.MustParseURL(grandparentHL)}, nil)

		anchorLinksetDoc := anchorEvent.Object().Document()
		require.NotNil(t, anchorLinksetDoc)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, vocab.UnmarshalFromDoc(anchorLinksetDoc, anchorLinkset))
		require.NotNil(t, anchorLinkset.Link())

		parents, err := handler.getUnprocessedParentAnchors(hl, anchorLinkset.Link())
		require.NoError(t, err)
		require.Empty(t, parents)
	})

	t.Run("Two parents unprocessed -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturnsOnCall(0, []byte(testutil.GetCanonical(t, sampleParentAnchorLinkset)),
			parentHL, nil)
		casResolver.ResolveReturnsOnCall(1, []byte(testutil.GetCanonical(t, sampleGrandparentAnchorLinkset)),
			grandparentHL, nil)

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleAnchorEvent), anchorEvent))

		anchorLinksetDoc := anchorEvent.Object().Document()
		require.NotNil(t, anchorLinksetDoc)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, vocab.UnmarshalFromDoc(anchorLinksetDoc, anchorLinkset))
		require.NotNil(t, anchorLinkset.Link())

		parents, err := handler.getUnprocessedParentAnchors(hl, anchorLinkset.Link())
		require.NoError(t, err)
		require.Len(t, parents, 2)
		require.Equal(t, grandparentHL, parents[0].Hashlink)
		require.Equal(t, parentHL, parents[1].Hashlink)
	})

	t.Run("Duplicate parents -> Success", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturns([]byte(testutil.GetCanonical(t, sampleGrandparentAnchorLinkset)), grandparentHL, nil)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(sampleAnchorLinksetDuplicateParents), anchorLinkset))

		parents, err := handler.getUnprocessedParentAnchors(hl, anchorLinkset.Link())
		require.NoError(t, err)
		require.Len(t, parents, 1)
	})

	t.Run("Unmarshal -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		errExpected := errors.New("injected unmarshal error")

		handler.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		anchorEvent := &vocab.AnchorEventType{}

		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorEvent), anchorEvent))
		require.NotNil(t, anchorEvent.Object().Document())

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, vocab.UnmarshalFromDoc(anchorEvent.Object().Document(), anchorLinkset))

		anchorLink := anchorLinkset.Link()
		require.NotNil(t, anchorLink)

		anchorLinkStore.GetLinksReturns(nil, nil)

		casResolver.ResolveReturns([]byte(testutil.GetCanonical(t, sampleAnchorEvent)), grandparentHL, nil)

		_, err := handler.getUnprocessedParentAnchors(hl, anchorLink)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Invalid parent hashlink -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(sampleAnchorLinksetInvalidParent), anchorLinkset))

		anchorLinkStore.GetLinksReturns(nil, nil)

		_, err := handler.getUnprocessedParentAnchors(parentHL, anchorLinkset.Link())
		require.Error(t, err)
		require.Contains(t, err.Error(), "must start with 'hl:' prefix")
	})

	t.Run("GetLinks -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		errExpected := errors.New("injected GetLinks error")

		anchorLinkStore.GetLinksReturns(nil, errExpected)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorLinkset), anchorLinkset))

		_, err := handler.getUnprocessedParentAnchors(parentHL, anchorLinkset.Link())
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("CAS Resolver -> Error", func(t *testing.T) {
		casResolver := &mocks2.CASResolver{}
		anchorLinkStore := &orbmocks.AnchorLinkStore{}

		handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
			time.Second, anchorLinkStore, registry)
		require.NotNil(t, handler)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(sampleParentAnchorLinkset), anchorLinkset))

		errExpected := errors.New("injected Resolve error")

		casResolver.ResolveReturns(nil, "", errExpected)

		_, err := handler.getUnprocessedParentAnchors(parentHL, anchorLinkset.Link())
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestAnchorEventHandler_processAnchorEvent(t *testing.T) {
	casResolver := &mocks2.CASResolver{}
	anchorLinkStore := &orbmocks.AnchorLinkStore{}

	handler := New(&anchormocks.AnchorPublisher{}, casResolver, testutil.GetLoader(t),
		time.Second, anchorLinkStore, generator.NewRegistry())
	require.NotNil(t, handler)

	t.Run("success", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(sampleGrandparentAnchorLinkset), anchorLinkset))

		err := handler.processAnchorEvent(&anchorInfo{
			AnchorInfo: &info.AnchorInfo{},
			anchorLink: anchorLinkset.Link(),
		})
		require.NoError(t, err)
	})

	t.Run("no replies -> error", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetNoReplies), anchorLinkset))

		err := handler.processAnchorEvent(&anchorInfo{
			AnchorInfo: &info.AnchorInfo{},
			anchorLink: anchorLinkset.Link(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no replies in anchor link")
	})

	t.Run("invalid original content -> error", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetInvalidContent), anchorLinkset))

		err := handler.processAnchorEvent(&anchorInfo{
			AnchorInfo: &info.AnchorInfo{},
			anchorLink: anchorLinkset.Link(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported media type")
	})

	t.Run("unsupported profile -> error", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetUnsupportedProfile), anchorLinkset))

		err := handler.processAnchorEvent(&anchorInfo{
			AnchorInfo: &info.AnchorInfo{},
			anchorLink: anchorLinkset.Link(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "generator not found")
	})

	t.Run("invalid anchor credential -> error", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetInvalidVC), anchorLinkset))

		err := handler.processAnchorEvent(&anchorInfo{
			AnchorInfo: &info.AnchorInfo{},
			anchorLink: anchorLinkset.Link(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "validate credential subject for anchor")
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
		time.Second, anchorLinkStore, generator.NewRegistry())
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

	resourceHash, err = casClient.Write([]byte(testutil.GetCanonical(t, sampleAnchorEvent)))
	require.NoError(t, err)

	t.Logf("Stored grandparent anchor: %s", resourceHash)

	return casClient
}

//nolint:lll
const sampleAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "object": {
    "linkset": [
      {
        "anchor": "hl:uEiDzKYFbc6tntXzq7R2uJBA_wI6LhcSDUbXIJmy1zawvpw",
        "author": "https://orb.domain1.com/services/orb",
        "original": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiDCkyqOTtGXLOLOsInc_t6X5NMRebZSWlFXfvJmx7Bujg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%2C%22previous%22%3A%5B%22hl%3AuEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%2C%22previous%22%3A%5B%22hl%3AuEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg%22%5D%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "profile": "https://w3id.org/orb#v0",
        "related": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiDzKYFbc6tntXzq7R2uJBA_wI6LhcSDUbXIJmy1zawvpw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRElSeVp4cE9ZRHRVbFNzcjZ3VS1ZYnQxN1RyQkVxQ25ybFZKc1R0Q2phcGd4QmlwZnM6Ly9iYWZrcmVpZ2lpNHRoZGpoZ2FvMnVzdXZzeDJ5Zmh6cTN3NXBuaGxhcmZpZmh2emt1dG1qM2lrZzJ1eQ%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDCkyqOTtGXLOLOsInc_t6X5NMRebZSWlFXfvJmx7Bujg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRENreXFPVHRHWExPTE9zSW5jX3Q2WDVOTVJlYlpTV2xGWGZ2Sm14N0J1amd4QmlwZnM6Ly9iYWZrcmVpZ2NzbXZpNHR3cnM0d29mdHZxcmhvcDV4dXg0dGpyYzZud2tqbmZjdjM2Nmp0bXBtZG9yeQ%22%7D%5D%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "replies": [
          {
            "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiDCkyqOTtGXLOLOsInc_t6X5NMRebZSWlFXfvJmx7Bujg%22%2C%22id%22%3A%22hl%3AuEiDzKYFbc6tntXzq7R2uJBA_wI6LhcSDUbXIJmy1zawvpw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Ffbe7b4ff-788d-409f-846a-1f41fb9cb607%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A18.6338532Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A18.663Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zMLgPKMdb5CZPy2fR19dLvcQmVPSidKhrN3ocYgE4TbFGP3gKjAKd2HoLk1mzmMz5sKge7r5mPoCy3WHuDRoqn2U%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A18.8748913Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z4dAdDepEgQjQ97qPRfjZq2WD16E2u51LnTm2uWN2Zu6G7Fdi66XdKbajy2FxLGXBu8bUzZ22LQBMZ7BJpV9t7qWP%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
            "type": "application/ld+json"
          }
        ]
      }
    ]
  },
  "type": "AnchorEvent",
  "url": "hl:uEiDbYK4YRQLH0FiD0QpTwAwOYUvvkWu65zbib2SngzuYyA:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRGJZSzRZUlFMSDBGaUQwUXBUd0F3T1lVdnZrV3U2NXpiaWIyU25nenVZeUF4QmlwZnM6Ly9iYWZrcmVpZzNtY3hicXJpY3k3aWZyYTZyYmpqNGFkYW9tZmY2N2VsbHhsdHRueXRwbXN0eWdvNHl6YQ"
}`

//nolint:lll
const sampleParentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "object": {
    "linkset": [
      {
        "anchor": "hl:uEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA",
        "author": "https://orb.domain1.com/services/orb",
        "original": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%2C%22previous%22%3A%5B%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%2C%22previous%22%3A%5B%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%22%5D%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "profile": "https://w3id.org/orb#v0",
        "related": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRHBVcU54Nnl6X1Zya0RHTWlLZHlkczNRb3RkejN4R1VmSDdQWnBaTnNIZlF4QmlwZnM6Ly9iYWZrcmVpaGpra3J4ZDJ6bTc1bGxzYXl5emNmaG9qM20zdWZjMjV6NTZlbXVwcjdtNnp1d2p3eWhwdQ%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRC0za1NJbXlzVHVQYmpBZXJOMC0xcDNyU1VGT1RCODZ0bGFLZnV4QVNrcUF4QmlwZnM6Ly9iYWZrcmVpaDYzemNpcmd6bGNvNHBueXliNWxnNWgzbGozMjJqaWZoZXloejJ3emxpdTd4bWliZmV2YQ%22%7D%5D%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "replies": [
          {
            "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%22%2C%22id%22%3A%22hl%3AuEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2F680798be-2b67-4c49-8590-961f8946ddd2%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A13.643727Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A13.66Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z5aUDn53GzhLAcM2LZ1PPX2XTCreAaHCyHvnA1XhDwUyuBcYqBZihCcRqcWSF1JacihXSmD25Tnr9GLoUJax8CCAg%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A13.8227356Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z4LwejC2NEqSyt73W8vTv5Fz7mnfDpZXEjWu8RSb88DLZAhER7s96b7QkMNXV9xGkuvDBu8s9hj5Mtzz7J2dgs36R%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
            "type": "application/ld+json"
          }
        ]
      }
    ]
  },
  "type": "AnchorEvent",
  "url": "hl:uEiDIRyZxpOYDtUlSsr6wU-Ybt17TrBEqCnrlVJsTtCjapg:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRElSeVp4cE9ZRHRVbFNzcjZ3VS1ZYnQxN1RyQkVxQ25ybFZKc1R0Q2phcGd4QmlwZnM6Ly9iYWZrcmVpZ2lpNHRoZGpoZ2FvMnVzdXZzeDJ5Zmh6cTN3NXBuaGxhcmZpZmh2emt1dG1qM2lrZzJ1eQ"
}`

//nolint:lll
const sampleParentAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%2C%22previous%22%3A%5B%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%2C%22previous%22%3A%5B%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%22%5D%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRHBVcU54Nnl6X1Zya0RHTWlLZHlkczNRb3RkejN4R1VmSDdQWnBaTnNIZlF4QmlwZnM6Ly9iYWZrcmVpaGpra3J4ZDJ6bTc1bGxzYXl5emNmaG9qM20zdWZjMjV6NTZlbXVwcjdtNnp1d2p3eWhwdQ%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRC0za1NJbXlzVHVQYmpBZXJOMC0xcDNyU1VGT1RCODZ0bGFLZnV4QVNrcUF4QmlwZnM6Ly9iYWZrcmVpaDYzemNpcmd6bGNvNHBueXliNWxnNWgzbGozMjJqaWZoZXloejJ3emxpdTd4bWliZmV2YQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiD-3kSImysTuPbjAerN0-1p3rSUFOTB86tlaKfuxASkqA%22%2C%22id%22%3A%22hl%3AuEiAf5FKXCAwRBsd-1qf1Em2YiTuK6JxBPS4I5LRtg9EIGA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2F680798be-2b67-4c49-8590-961f8946ddd2%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A13.643727Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A13.66Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z5aUDn53GzhLAcM2LZ1PPX2XTCreAaHCyHvnA1XhDwUyuBcYqBZihCcRqcWSF1JacihXSmD25Tnr9GLoUJax8CCAg%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A13.8227356Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z4LwejC2NEqSyt73W8vTv5Fz7mnfDpZXEjWu8RSb88DLZAhER7s96b7QkMNXV9xGkuvDBu8s9hj5Mtzz7J2dgs36R%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const sampleGrandparentAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "object": {
    "linkset": [
      {
        "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
        "author": "https://orb.domain1.com/services/orb",
        "original": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "profile": "https://w3id.org/orb#v0",
        "related": [
          {
            "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
            "type": "application/linkset+json"
          }
        ],
        "replies": [
          {
            "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22id%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fb1cf5b8e-a236-4410-8cab-56f66e3363c6%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A10.5475141Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A10.569Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zkaYZHbisAJpQ6BtBEKJtcMcqZW1D2oEeDo3RfAHhz9MNwM42VatU2M8haoMDDjekUHB5uyUZt76AtPaCT4gcz29%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A10.7557806Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3gXGJPpe1CgPNve23hWs78ySbKcy6UDDvxg7CfQSgAfdpVM37zWXAQPpU3ppUhSwhUrUZW345iDL6TrmhYBzV8K4%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
            "type": "application/ld+json"
          }
        ]
      }
    ]
  },
  "type": "AnchorEvent",
  "url": "hl:uEiDpUqNx6yz_VrkDGMiKdyds3Qotdz3xGUfH7PZpZNsHfQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRHBVcU54Nnl6X1Zya0RHTWlLZHlkczNRb3RkejN4R1VmSDdQWnBaTnNIZlF4QmlwZnM6Ly9iYWZrcmVpaGpra3J4ZDJ6bTc1bGxzYXl5emNmaG9qM20zdWZjMjV6NTZlbXVwcjdtNnp1d2p3eWhwdQ"
}`

//nolint:lll
const sampleGrandparentAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22id%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fb1cf5b8e-a236-4410-8cab-56f66e3363c6%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A10.5475141Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A10.569Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zkaYZHbisAJpQ6BtBEKJtcMcqZW1D2oEeDo3RfAHhz9MNwM42VatU2M8haoMDDjekUHB5uyUZt76AtPaCT4gcz29%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A10.7557806Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3gXGJPpe1CgPNve23hWs78ySbKcy6UDDvxg7CfQSgAfdpVM37zWXAQPpU3ppUhSwhUrUZW345iDL6TrmhYBzV8K4%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const sampleAnchorLinksetDuplicateParents = `{
  "linkset": [
    {
      "anchor": "hl:uEiBpFIScGjmr9GEs2-WIQ-SYZZdfsN_iePnO4kxtRR9A5Q",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBRe-7-dP9BuarMgsnh0ORnGWi6moc4GmQet-pQUeJjLQ%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%3AEiDSqf8owKb84KDjRbIemw-Sv-UoyPcsyPNFEQ9rzT-Uag%22%2C%22previous%22%3A%22hl%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%3AEiApcqrvEntohzA1NGNYO9l3N7yyR-dfvotjxTTAzGlTUQ%22%2C%22previous%22%3A%22hl%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBpFIScGjmr9GEs2-WIQ-SYZZdfsN_iePnO4kxtRR9A5Q%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpREItTmg0a3hQMlVJempDLW9MYkVhVzRiSENZYUZDOVdndlB0YnRNdHZNdUF4QmlwZnM6Ly9iYWZrcmVpZ2I3ZG1ocmV5dDZ6aWl6eXlsNWlmd3lydXc0Z3k0ZXluYmlsMndxbHo2MjN3dGZ3Nm14YQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiDB-Nh4kxP2UIzjC-oLbEaW4bHCYaFC9WgvPtbtMtvMuA%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpREItTmg0a3hQMlVJempDLW9MYkVhVzRiSENZYUZDOVdndlB0YnRNdHZNdUF4QmlwZnM6Ly9iYWZrcmVpZ2I3ZG1ocmV5dDZ6aWl6eXlsNWlmd3lydXc0Z3k0ZXluYmlsMndxbHo2MjN3dGZ3Nm14YQ%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiBRe-7-dP9BuarMgsnh0ORnGWi6moc4GmQet-pQUeJjLQ%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQlJlLTctZFA5QnVhck1nc25oME9SbkdXaTZtb2M0R21RZXQtcFFVZUpqTFF4QmlwZnM6Ly9iYWZrcmVpY3JwcHhwNDVoN2lnNDJ2dGVjemhxNWJ6ZGhkZnVsdmd1aGhhbmdpaHZ4NWppZmR5dGRmdQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiBpFIScGjmr9GEs2-WIQ-SYZZdfsN_iePnO4kxtRR9A5Q%22%2C%22id%22%3A%22https%3A%2F%2Forb2.domain1.com%2Fvc%2F9e24fe54-097b-418b-8a3f-e948a15bbfb6%22%2C%22issuanceDate%22%3A%222022-03-16T18%3A20%3A38.703155915Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb2.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-03-16T18%3A20%3A38.712Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22aHF4OpYMArTIJLupKMumfXzu_CHgGx40p9haG6N__6bRVNEyFvWEmXvykcQ3DkTy1LVTi6pL3FQfMiCGyfvzCA%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%2C%7B%22created%22%3A%222022-03-16T18%3A20%3A38.788086226Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22IMbTYbfpwColUBcD2uzqdTBmuCbauVTmYykPs_ozmf77rN6AEouTZvXmmL8vd-NJuZhQvnG-Vx6RVhrS7DPoBw%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const sampleAnchorLinksetInvalidParent = `{
  "linkset": [
    {
      "anchor": "hl:uEiDhi1oX6K76A1ch5WPu2wdNLcizCx08EypO0taw9KHOGw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAOVteziujP52prEAQrRuE5CXGQ1XR6xwDP86SMPWTOPw%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiBdCxP8fh2R84KBL4n-GVO5TbjIPTxd-h55XFsw6QZbFA%3AEiDSqf8owKb84KDjRbIemw-Sv-UoyPcsyPNFEQ9rzT-Uag%22%2C%22previous%22%3A%22hl%3AuEiBdCxP8fh2R84KBL4n-GVO5TbjIPTxd-h55XFsw6QZbFA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiBdCxP8fh2R84KBL4n-GVO5TbjIPTxd-h55XFsw6QZbFA%3AEiApcqrvEntohzA1NGNYO9l3N7yyR-dfvotjxTTAzGlTUQ%22%2C%22previous%22%3A%22hl%3AuEiBdCxP8fh2R84KBL4n-GVO5TbjIPTxd-h55XFsw6QZbFA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiDhi1oX6K76A1ch5WPu2wdNLcizCx08EypO0taw9KHOGw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22http%3A%2F%2Fdomain1.com%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiAOVteziujP52prEAQrRuE5CXGQ1XR6xwDP86SMPWTOPw%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQU9WdGV6aXVqUDUycHJFQVFyUnVFNUNYR1ExWFI2eHdEUDg2U01QV1RPUHd4QmlwZnM6Ly9iYWZrcmVpYW9rM2wzaGN4aXo3dHd1MnlxYXF2dW55anpiZnl6YnZsdXBsZHFidDd0dXNnZDJ6Z29oNA%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiDhi1oX6K76A1ch5WPu2wdNLcizCx08EypO0taw9KHOGw%22%2C%22id%22%3A%22https%3A%2F%2Forb2.domain1.com%2Fvc%2F01331215-0839-4679-baa2-ba4481bac47b%22%2C%22issuanceDate%22%3A%222022-03-16T18%3A20%3A43.675143863Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb2.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-03-16T18%3A20%3A43.686Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22h7wjce2r6fH8ygSJGkm1yRZ_AvubDiodzn22osuCbYb5RCQaXoEmDtOf1oZMosO1vdeTcobi-CeW77J8_xYrAg%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%2C%7B%22created%22%3A%222022-03-16T18%3A20%3A43.787088993Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%229griFoChmta0rOXdHJ6WJjoXuxR8efjg9TeqzIyZqP986I9CU9I3a9wf-xVKusNa4ql7NCcvTLCXTUnQbMh2Cg%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const anchorLinksetNoReplies = `{
  "linkset": [
    {
      "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const anchorLinksetInvalidContent = `{
  "linkset": [
    {
      "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:unsupported,xxxxx",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22id%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fb1cf5b8e-a236-4410-8cab-56f66e3363c6%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A10.5475141Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A10.569Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zkaYZHbisAJpQ6BtBEKJtcMcqZW1D2oEeDo3RfAHhz9MNwM42VatU2M8haoMDDjekUHB5uyUZt76AtPaCT4gcz29%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A10.7557806Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3gXGJPpe1CgPNve23hWs78ySbKcy6UDDvxg7CfQSgAfdpVM37zWXAQPpU3ppUhSwhUrUZW345iDL6TrmhYBzV8K4%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const anchorLinksetUnsupportedProfile = `{
  "linkset": [
    {
      "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#vXXX",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22id%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fb1cf5b8e-a236-4410-8cab-56f66e3363c6%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A10.5475141Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A10.569Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zkaYZHbisAJpQ6BtBEKJtcMcqZW1D2oEeDo3RfAHhz9MNwM42VatU2M8haoMDDjekUHB5uyUZt76AtPaCT4gcz29%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A10.7557806Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3gXGJPpe1CgPNve23hWs78ySbKcy6UDDvxg7CfQSgAfdpVM37zWXAQPpU3ppUhSwhUrUZW345iDL6TrmhYBzV8K4%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

//nolint:lll
const anchorLinksetInvalidVC = `{
  "linkset": [
    {
      "anchor": "hl:uEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC0Iu10PDXwr5XIHgos9TZo1a1N13tq9V5XEk6EePWGkQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCP0F5n9PB2tuEPFCc7Oyob_itqrvdfGk_UphBOQ9rZQA%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiD07i6t3Cf31sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ0d6dUFZMU0wMXVNNm1DX3ZKRFVjOGlpSlhNeHFHeGw1YUJzV3FjcldmSWd4QmlwZnM6Ly9iYWZrcmVpZWd6M3FicnZnbmd3NG01anFsN3BlcTJyejRyaXJmb215MnEzZGY0d3FneXd2aGZubTdlaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiCGzuAY1M01uM6mC_vJDUc8iiJXMxqGxl5aBsWqcrWfIg%22%2C%22id%22%3A%22hl%3AuEiD07i6txxxx1sbTepJnigcbM4jVcaT6YqcWMWgDVuiwaw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fb1cf5b8e-a236-4410-8cab-56f66e3363c6%22%2C%22issuanceDate%22%3A%222022-07-19T17%3A38%3A10.5475141Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-07-19T17%3A38%3A10.569Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22zkaYZHbisAJpQ6BtBEKJtcMcqZW1D2oEeDo3RfAHhz9MNwM42VatU2M8haoMDDjekUHB5uyUZt76AtPaCT4gcz29%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23GJqG8xWJ4c4NGedg1-S_4FdsPjjFiV2GpZ0muPC_dv0%22%7D%2C%7B%22created%22%3A%222022-07-19T17%3A38%3A10.7557806Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3gXGJPpe1CgPNve23hWs78ySbKcy6UDDvxg7CfQSgAfdpVM37zWXAQPpU3ppUhSwhUrUZW345iDL6TrmhYBzV8K4%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23Tq-S3o_R8fNoiMHPTfWx0Evigk2mPWpnDdsN_biBNqg%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
