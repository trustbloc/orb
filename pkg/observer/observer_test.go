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
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/anchor/activity"
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

const casLink = "https://domain.com/cas"

func TestNew(t *testing.T) {
	errExpected := errors.New("injected pub-sub error")

	ps := &orbmocks.PubSub{}
	ps.SubscribeReturns(nil, errExpected)

	providers := &Providers{
		DidAnchors: memdidanchor.New(),
		PubSub:     ps,
		Metrics:    &orbmocks.MetricsProvider{},
	}

	o, err := New(providers)
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
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		prevAnchors := make(map[string]string)
		prevAnchors["did1"] = ""
		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "core1", PreviousAnchors: prevAnchors}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://example.com/services/orb",
		}

		prevAnchors = make(map[string]string)
		prevAnchors["did2"] = ""
		payload2 := subject.Payload{Namespace: namespace2, Version: 1, CoreIndex: "core2", PreviousAnchors: prevAnchors}

		c, err = buildCredential(&payload2)
		require.NoError(t, err)

		cid, err = anchorGraph.Add(c)
		require.NoError(t, err)
		anchor2 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload3 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "core3", PreviousAnchors: prevAnchors}

		c, err = buildCredential(&payload3)
		require.NoError(t, err)

		cid, err = anchorGraph.Add(c)
		require.NoError(t, err)

		anchor3 := &anchorinfo.AnchorInfo{
			Hashlink:      cid,
			LocalHashlink: cid,
			AttributedTo:  "https://orb.domain2.com/services/orb",
		}

		casResolver := &protomocks.CASResolver{}
		casResolver.ResolveReturns([]byte(anchorCredential), "", nil)

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
		}

		o, err := New(providers, WithDiscoveryDomain("webcas:shared.domain.com"))
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "xyz"
		did2 := "abc"

		previousAnchors := make(map[string]string)
		previousAnchors[did1] = ""
		previousAnchors[did2] = ""

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "jkh"

		previousAnchors := make(map[string]string)
		previousAnchors[did1] = ""

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)

		previousAnchors[did1] = cid

		payload2 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		c, err = buildCredential(&payload2)
		require.NoError(t, err)

		cid, err = anchorGraph.Add(c)
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}
		anchorGraph := graph.New(graphProviders)

		did := "123"

		previousDIDAnchors := make(map[string]string)
		previousDIDAnchors[did] = ""

		payload1 := subject.Payload{
			Namespace: namespace1,
			Version:   1, CoreIndex: "address",
			PreviousAnchors: previousDIDAnchors,
		}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)

		anchor := &anchorinfo.AnchorInfo{Hashlink: cid}

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "123"
		did2 := "abc"

		previousAnchors := make(map[string]string)
		previousAnchors[did1] = ""
		previousAnchors[did2] = ""

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		prevAnchors := make(map[string]string)
		prevAnchors["suffix"] = ""

		payload1 := subject.Payload{
			Namespace:       namespace1,
			Version:         1,
			CoreIndex:       "core1",
			PreviousAnchors: prevAnchors,
		}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
		require.NoError(t, err)
		anchor1 := &anchorinfo.AnchorInfo{Hashlink: cid}

		payload2 := subject.Payload{
			Namespace:       namespace2,
			Version:         1,
			CoreIndex:       "core2",
			PreviousAnchors: prevAnchors,
		}

		c, err = buildCredential(&payload2)
		require.NoError(t, err)

		cid, err = anchorGraph.Add(c)
		require.NoError(t, err)
		anchor2 := &anchorinfo.AnchorInfo{Hashlink: cid}

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             &mockDidAnchor{Err: fmt.Errorf("did anchor error")},
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		anchorGraph := &orbmocks.AnchorGraph{}
		anchorGraph.GetDidAnchorsReturns([]graph.Anchor{{Info: &verifiable.Credential{}}}, nil)

		providers := &Providers{
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			PubSub:                 mempubsub.New(mempubsub.DefaultConfig()),
			Metrics:                &orbmocks.MetricsProvider{},
		}

		o, err := New(providers)
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
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: casClient,
			CasResolver: casresolver.New(casClient, nil,
				casresolver.NewWebCASResolver(
					transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
						transport.DefaultSigner(), transport.DefaultSigner()),
					webfingerclient.New(), "https"), &orbmocks.MetricsProvider{}),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "xyz"

		previousAnchors := make(map[string]string)
		previousAnchors[did1] = ""

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		c, err := buildCredential(&payload1)
		require.NoError(t, err)

		cid, err := anchorGraph.Add(c)
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
		}

		o, err := New(providers)
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
	}

	o, e := New(providers)
	require.NotNil(t, o)
	require.NoError(t, e)

	t.Run("Success", func(t *testing.T) {
		casResolver.ResolveReturns([]byte(anchorCredential), "", nil)

		actor, err := o.resolveActorFromHashlink(hl)
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain2.com/services/orb", actor.String())
	})

	t.Run("CAS resolve error", func(t *testing.T) {
		errExpected := errors.New("injected resolve error")

		casResolver.ResolveReturns(nil, "", errExpected)

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Parse VC error", func(t *testing.T) {
		casResolver.ResolveReturns([]byte(anchorCredentialInvalid), "", nil)

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("No subject in VC error", func(t *testing.T) {
		casResolver.ResolveReturns([]byte(anchorCredentialNoSubject), "", nil)

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), "\"attributedTo\" field not found in anchor credential")
	})

	t.Run("WebFinger resolve error", func(t *testing.T) {
		errExpected := errors.New("injected WebFinger resolve error")

		casResolver.ResolveReturns([]byte(anchorCredential), "", nil)
		wfResolver.Err = errExpected

		defer func() {
			wfResolver.Err = nil
		}()

		_, err := o.resolveActorFromHashlink(hl)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func buildCredential(payload *subject.Payload) (*verifiable.Credential, error) {
	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	act, err := activity.BuildActivityFromPayload(payload)
	if err != nil {
		return nil, err
	}

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: act,
		Issuer: verifiable.Issuer{
			ID: "http://orb.domain.com",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	return vc, nil
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}

type mockDidAnchor struct {
	Err error
}

func (m *mockDidAnchor) PutBulk(_ []string, _ string) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

//nolint:lll
const anchorCredential = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "credentialSubject": {
    "attachment": [
      {
        "generator": "https://w3id.org/orb#v0",
        "resources": [
          "did:orb:uAAA:EiCj5WmLy82AIT_GD5KaRC_eLcx5gBRnMSnGfi7iv7cGEw"
        ],
        "type": "AnchorIndex",
        "url": "hl:uEiBAk1gK831wNVhPHCG92OSbIOSpsMCBrCYjjEySpbbwrg:uoQ-BeDVpcGZzOi8vUW1YNHlmSFpobWJxaGZFRWFhMzRjSG5EV2FTTEtETm5SRjRUbXdiNlBnenNISg"
      },
      {
        "type": "AnchorObject",
        "url": "hl:uEiBFMUG4hvCj7ffrVKYDksJNz-t5DEZCpV_qMFrPYVXz8g:uoQ-BeDVpcGZzOi8vUW1lTlJTQ2E3RVMyWWJKTFY5VW5NanNvdk5WM2cyRW1iV2dycHRza3NoRVhYUQ"
      },
      {
        "type": "AnchorObject",
        "url": "hl:uEiD0JfD_5SOENYh4E37BSbIzHiM7bOMIf3_mWdefRaUiwQ:uoQ-BeDVpcGZzOi8vUW1QWlhHdzI4QjRyU2M4bzJObXhlTExhbnRzUGRkRmt0bzhZWG5BR2lYZ3QyVg"
      }
    ],
    "attributedTo": "https://orb.domain2.com/services/orb",
    "published": "2021-09-10T14:04:11.086419939Z",
    "type": "AnchorEvent"
  },
  "id": "http://orb.domain2.com/vc/18d68624-3011-4365-a938-3703e9cac868",
  "issuanceDate": "2021-09-10T14:04:11.086419939Z",
  "issuer": "http://orb.domain2.com",
  "proof": [
    {
      "created": "2021-09-10T14:04:11.399Z",
      "domain": "http://orb.vct:8077/maple2020",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sl4EKDREkRRnjiAbEXNc8onzlFPlXI-NgJgxlPcRXFZjTQ9W5ssnfdHLXnzJBZtAlY-icMc73MvKGxAE0tG0Cw",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain1.com#orb1key"
    },
    {
      "created": "2021-09-10T14:04:11.399Z",
      "domain": "http://orb.vct:8077/maple2020",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sl4EKDREkRRnjiAbEXNc8onzlFPlXI-NgJgxlPcRXFZjTQ9W5ssnfdHLXnzJBZtAlY-icMc73MvKGxAE0tG0Cw",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain1.com#orb1key"
    }
  ],
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

const anchorCredentialInvalid = `{
  "@context": [
`

//nolint:lll
const anchorCredentialNoSubject = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "credentialSubject": {},
  "id": "http://orb.domain2.com/vc/18d68624-3011-4365-a938-3703e9cac868",
  "issuanceDate": "2021-09-10T14:04:11.086419939Z",
  "issuer": "http://orb.domain2.com",
  "proof": [
    {
      "created": "2021-09-10T14:04:11.399Z",
      "domain": "http://orb.vct:8077/maple2020",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sl4EKDREkRRnjiAbEXNc8onzlFPlXI-NgJgxlPcRXFZjTQ9W5ssnfdHLXnzJBZtAlY-icMc73MvKGxAE0tG0Cw",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain1.com#orb1key"
    },
    {
      "created": "2021-09-10T14:04:11.399Z",
      "domain": "http://orb.vct:8077/maple2020",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sl4EKDREkRRnjiAbEXNc8onzlFPlXI-NgJgxlPcRXFZjTQ9W5ssnfdHLXnzJBZtAlY-icMc73MvKGxAE0tG0Cw",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain1.com#orb1key"
    }
  ],
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`
