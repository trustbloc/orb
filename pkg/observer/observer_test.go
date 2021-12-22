/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	protomocks "github.com/trustbloc/orb/pkg/protocolversion/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/store/cas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

//go:generate counterfeiter -o ../mocks/anchorgraph.gen.go --fake-name AnchorGraph . AnchorGraph
//go:generate counterfeiter -o ../mocks/anchorlinkstore.gen.go --fake-name AnchorLinkStore . linkStore

type linkStore interface { //nolint:deadcode,unused
	PutLinks(links []*url.URL) error
	GetLinks(anchorHash string) ([]*url.URL, error)
	DeleteLinks(links []*url.URL) error
}

const casLink = "https://domain.com/cas"

var serviceIRI = testutil.MustParseURL("https://domain1.com/services/orb")

func TestNew(t *testing.T) {
	errExpected := errors.New("injected pub-sub error")

	ps := &orbmocks.PubSub{}
	ps.SubscribeWithOptsReturns(nil, errExpected)

	providers := &Providers{
		DidAnchors: memdidanchor.New(),
		PubSub:     ps,
		Metrics:    &orbmocks.MetricsProvider{},
	}

	o, err := New(serviceIRI, providers)
	require.Error(t, err)
	require.Contains(t, err.Error(), errExpected.Error())
	require.Nil(t, o)
}

func TestStartObserver(t *testing.T) {
	const (
		namespace1 = "did:orb"
		namespace2 = "did:test"
	)

	t.Run("test channel close", func(t *testing.T) {
		providers := &Providers{
			DidAnchors: memdidanchor.New(),
			PubSub:     mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:    &orbmocks.MetricsProvider{},
			Pkf:        pubKeyFetcherFnc,
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)
		require.NotNil(t, o.Publisher())

		o.Start()
		defer o.Stop()

		time.Sleep(200 * time.Millisecond)
	})

	t.Run("success - process batch", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		prevAnchors := []*subject.SuffixAnchor{
			{Suffix: "did1"},
		}

		payload1 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "core1", PreviousAnchors: prevAnchors}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://example.com/services/orb",
		}

		prevAnchors = []*subject.SuffixAnchor{
			{Suffix: "did2"},
		}

		payload2 := subject.Payload{Namespace: namespace2, Version: 1, CoreIndex: "core2", PreviousAnchors: prevAnchors}

		cid, err = anchorGraph.Add(newMockAnchorEvent(t, &payload2))
		require.NoError(t, err)
		anchor2 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload3 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "core3", PreviousAnchors: prevAnchors}

		cid, err = anchorGraph.Add(newMockAnchorEvent(t, &payload3))
		require.NoError(t, err)

		anchor3 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://orb.domain2.com/services/orb",
		}

		casResolver := &protomocks.CASResolver{}
		casResolver.ResolveReturns([]byte(anchorEvent), "", nil)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			Outbox:                 func() Outbox { return apmocks.NewOutbox() },
			WebFingerResolver:      &apmocks.WebFingerResolver{},
			CASResolver:            casResolver,
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers, WithDiscoveryDomain("webcas:shared.domain.com"))
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishAnchor(anchor1))
		require.NoError(t, o.pubSub.PublishAnchor(anchor2))
		require.NoError(t, o.pubSub.PublishAnchor(anchor3))

		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("success - process did (multiple, just create)", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "xyz"
		did2 := "abc"

		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: did1},
			{Suffix: did2},
		}

		payload1 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			Pkf:                    pubKeyFetcherFnc,
			DocLoader:              testutil.GetLoader(t),
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID(cid+":"+did1))
		require.NoError(t, o.pubSub.PublishDID(cid+":"+did2))

		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("success - process did with previous anchors", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "jkh"

		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: did1},
		}

		payload1 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)

		previousAnchors[0].Anchor = cid

		payload2 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, err = anchorGraph.Add(newMockAnchorEvent(t, &payload2))
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID(cid+":"+did1))
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("success - did and anchor", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}
		anchorGraph := graph.New(graphProviders)

		did := "123"

		previousDIDAnchors := []*subject.SuffixAnchor{
			{Suffix: did},
		}

		payload1 := subject.Payload{
			Namespace: namespace1,
			Version:   0, CoreIndex: "address",
			PreviousAnchors: previousDIDAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)

		anchor := &anchorinfo.AnchorInfo{Hashlink: cid}

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishAnchor(anchor))
		require.NoError(t, o.pubSub.PublishDID(cid+":"+did))
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("error - transaction processor error", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "123"
		did2 := "abc"

		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: did1},
			{Suffix: did2},
		}

		payload1 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID(cid+":"+did1))
		require.NoError(t, o.pubSub.PublishDID(cid+":"+did2))

		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("error - update did anchors error", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		prevAnchors := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "core1",
			PreviousAnchors: prevAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload2 := subject.Payload{
			Namespace:       namespace2,
			Version:         1,
			CoreIndex:       "core2",
			PreviousAnchors: prevAnchors,
		}

		cid, err = anchorGraph.Add(newMockAnchorEvent(t, &payload2))
		require.NoError(t, err)
		anchor2 := &anchorinfo.AnchorInfo{Hashlink: cid}

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             &mockDidAnchor{Err: fmt.Errorf("did anchor error")},
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishAnchor(anchor1))
		require.NoError(t, o.pubSub.PublishAnchor(anchor2))

		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 1, tp.ProcessCallCount())
	})

	t.Run("error - cid not found", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID("cid:did"))
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 0, tp.ProcessCallCount())
	})

	t.Run("error - invalid did format", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID("no-cid"))
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 0, tp.ProcessCallCount())
	})

	t.Run("PublishDID persistent error in process anchor -> ignore", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{
			Info: &vocab.AnchorEventType{},
		}}, nil)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID("cid:xyz"))
		time.Sleep(200 * time.Millisecond)

		require.Empty(t, tp.ProcessCallCount())
	})

	t.Run("PublishDID transient error in process anchor -> error", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}
		tp.ProcessReturns(orberrors.NewTransient(errors.New("injected processing error")))

		pc := mocks.NewMockProtocolClient()
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "xyz"

		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: did1},
		}

		payload1 := subject.Payload{Namespace: namespace1, Version: 0, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, err := anchorGraph.Add(newMockAnchorEvent(t, &payload1))
		require.NoError(t, err)

		pubSub := apmocks.NewPubSub()
		defer pubSub.Stop()

		undeliverableChan, err := pubSub.Subscribe(context.Background(), spi.UndeliverableTopic)
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 pubSub,
			Metrics:                &orbmocks.MetricsProvider{},
			DocLoader:              testutil.GetLoader(t),
			Pkf:                    pubKeyFetcherFnc,
			AnchorLinkStore:        &orbmocks.AnchorLinkStore{},
		}

		o, err := New(serviceIRI, providers)
		require.NotNil(t, o)
		require.NoError(t, err)

		o.Start()
		defer o.Stop()

		require.NoError(t, o.pubSub.PublishDID(cid+":"+did1))

		select {
		case msg := <-undeliverableChan:
			t.Logf("Got undeliverable message: %s", msg.UUID)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Expecting undeliverable message")
		}
	})
}

func TestResolveActorFromHashlink(t *testing.T) {
	const hl = "hl:uEiAFwmZwzDoQ0XpnsKVHwwAjGCJ6g1prSDwUEMsDKv86NQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWFmeWp0aGJ0YjJjZGl4" +
		"dXo1cXV2ZDRnYWJkZGFyaHZhMjJubmVkeWZhcXptYnN2N3oyZ3U"

	casResolver := &protomocks.CASResolver{}
	wfResolver := &apmocks.WebFingerResolver{}

	providers := &Providers{
		PubSub:            mempubsub.New(mempubsub.DefaultConfig()),
		WebFingerResolver: wfResolver,
		CASResolver:       casResolver,
		DocLoader:         testutil.GetLoader(t),
		Pkf:               pubKeyFetcherFnc,
		AnchorLinkStore:   &orbmocks.AnchorLinkStore{},
	}

	o, e := New(serviceIRI, providers)
	require.NotNil(t, o)
	require.NoError(t, e)

	t.Run("Success", func(t *testing.T) {
		casResolver.ResolveReturns([]byte(anchorEvent), "", nil)

		actor, err := o.resolveActorFromHashlink(hl)
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain1.com/services/orb", actor.String())
	})

	t.Run("CAS resolve error", func(t *testing.T) {
		errExpected := errors.New("injected resolve error")

		casResolver.ResolveReturns(nil, "", errExpected)

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Parse VC error", func(t *testing.T) {
		casResolver.ResolveReturns([]byte(anchorEventInvalid), "", nil)

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("WebFinger resolve error", func(t *testing.T) {
		errExpected := errors.New("injected WebFinger resolve error")

		casResolver.ResolveReturns([]byte(anchorEvent), "", nil)
		wfResolver.Err = errExpected

		defer func() {
			wfResolver.Err = nil
		}()

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func newMockAnchorEvent(t *testing.T, payload *subject.Payload) *vocab.AnchorEventType {
	t.Helper()

	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: &builder.CredentialSubject{
			ID: "hl:uEiBN4vd1lgKx_K93ltpdI32T6nIGlwXhJcSwbeVAg8NMxg:uoQ-BeEJpcGZzOi8vYmFma3JlaWNuNGwzeGxmcWN3aDZrNjU0dzNqb3NnN210NWp6YW5meWY0ZXM0am1kbjR2YWlocTJteXk", //nolint:lll
		},
		Issuer: verifiable.Issuer{
			ID: "http://orb.domain.com",
		},
		Issued: &util.TimeWrapper{Time: time.Now()},
	}

	contentObj, err := anchorevent.BuildContentObject(payload)
	require.NoError(t, err)

	act, err := anchorevent.BuildAnchorEvent(payload, contentObj.GeneratorID, contentObj.Payload,
		vocab.MustMarshalToDoc(vc))
	require.NoError(t, err)

	return act
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}

type mockDidAnchor struct {
	Err error
}

func (m *mockDidAnchor) PutBulk(_ []string, _ []bool, _ string) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

//nolint:lll
const anchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "index": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
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
  "type": "Info",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`

const anchorEventInvalid = `{
  "@context": [
`
