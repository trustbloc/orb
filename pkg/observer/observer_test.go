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
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
			PreviousAnchors: prevAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://example.com/services/orb",
		}

		prevAnchors = []*subject.SuffixAnchor{
			{Suffix: "did2"},
		}

		payload2 := subject.Payload{
			Namespace:       namespace2,
			Version:         1,
			CoreIndex:       "hl:uEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg",
			PreviousAnchors: prevAnchors,
		}

		cid, err = anchorGraph.Add(newMockAnchorLinkset(t, &payload2))
		require.NoError(t, err)
		anchor2 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload3 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ",
			PreviousAnchors: prevAnchors,
		}

		cid, err = anchorGraph.Add(newMockAnchorLinkset(t, &payload3))
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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
		require.NoError(t, err)

		previousAnchors[0].Anchor = cid

		payload2 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousAnchors,
		}

		cid, err = anchorGraph.Add(newMockAnchorLinkset(t, &payload2))
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
			Version:   0, CoreIndex: "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousDIDAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
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
			CoreIndex:       "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
			PreviousAnchors: prevAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload2 := subject.Payload{
			Namespace:       namespace2,
			Version:         1,
			CoreIndex:       "hl:uEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg",
			PreviousAnchors: prevAnchors,
		}

		cid, err = anchorGraph.Add(newMockAnchorLinkset(t, &payload2))
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
			Info: &linkset.Link{},
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
		tp.ProcessReturns(0, orberrors.NewTransient(errors.New("injected processing error")))

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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA",
			PreviousAnchors: previousAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
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

	t.Run("success - process duplicate operations", func(t *testing.T) {
		tp := &mocks.TxnProcessor{}
		tp.ProcessReturns(0, nil)

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

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         0,
			CoreIndex:       "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
			PreviousAnchors: prevAnchors,
		}

		cid, err := anchorGraph.Add(newMockAnchorLinkset(t, &payload1))
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://example.com/services/orb",
		}

		casResolver := &protomocks.CASResolver{}
		casResolver.ResolveReturns([]byte(anchorEvent), "", nil)

		t.Run("no operations", func(t *testing.T) {
			anchorLinkStore := &orbmocks.AnchorLinkStore{}
			anchorLinkStore.GetLinksReturns([]*url.URL{testutil.MustParseURL(anchor1.Hashlink)}, nil)

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
				AnchorLinkStore:        anchorLinkStore,
			}

			o, err := New(serviceIRI, providers, WithDiscoveryDomain("webcas:shared.domain.com"))
			require.NotNil(t, o)
			require.NoError(t, err)

			o.Start()
			defer o.Stop()

			require.NoError(t, o.pubSub.PublishAnchor(anchor1))

			time.Sleep(200 * time.Millisecond)

			require.Equal(t, 1, tp.ProcessCallCount())
		})

		t.Run("GetLinks error", func(t *testing.T) {
			anchorLinkStore := &orbmocks.AnchorLinkStore{}
			anchorLinkStore.GetLinksReturns(nil, errors.New("injected GetLinks error"))

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
				AnchorLinkStore:        anchorLinkStore,
			}

			o, err := New(serviceIRI, providers, WithDiscoveryDomain("webcas:shared.domain.com"))
			require.NotNil(t, o)
			require.NoError(t, err)

			o.Start()
			defer o.Stop()

			require.NoError(t, o.pubSub.PublishAnchor(anchor1))

			time.Sleep(200 * time.Millisecond)
		})
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

func newMockAnchorLinkset(t *testing.T, payload *subject.Payload) *linkset.Linkset {
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

	al, _, err := anchorlinkset.BuildAnchorLink(payload, datauri.MediaTypeDataURIGzipBase64,
		func(anchorHashlink string) (*verifiable.Credential, error) {
			return vc, nil
		},
	)
	require.NoError(t, err)

	return linkset.New(al)
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
  "linkset": [
    {
      "anchor": "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ1dLTTZxMWZHcWxwVzRIanBYWVA1S2JNOGJMUlF2X3daa0R3eVZfcnBfSlE%22%7D%2C%7B%22href%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ18xN0I3d0dHUTYxU1ppMlFEUU1wUWNCLWNxTFp6MW1kQk9QY1QzY0FaQkE%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fd53b1df9-1acf-4389-a006-0f88496afe46%22%2C%22issuanceDate%22%3A%222022-03-15T21%3A21%3A54.62437567Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-03-15T21%3A21%3A54.631Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22gRPF8XAA4iYMwl26RmFGUoN99wuUnD_igmvIlzzDpPRLVDtmA8wrNbUdJIAKKhyMJFju8OjciSGYMY_bDRjBAw%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%2C%7B%22created%22%3A%222022-03-15T21%3A21%3A54.744899145Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22FX58osRrwU11IrUfhVTi0ucrNEq05Cv94CQNvd8SdoY66fAjwU2--m8plvxwVnXmxnlV23i6htkq4qI8qrDgAA%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

const anchorEventInvalid = `{
  "@context": [
`
