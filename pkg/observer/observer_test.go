/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
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

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	caswriter "github.com/trustbloc/orb/pkg/cas/writer"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
)

func TestStartObserver(t *testing.T) {
	const (
		namespace1 = "ns1"
		namespace2 = "ns2"
	)

	t.Run("test channel close", func(t *testing.T) {
		anchorCh := make(chan []anchorinfo.AnchorInfo, 100)

		providers := &Providers{
			TxnProvider: mockLedger{registerForAnchor: anchorCh},
			DidAnchors:  memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		close(anchorCh)
		time.Sleep(200 * time.Millisecond)
	})

	t.Run("success - process batch", func(t *testing.T) {
		anchorCh := make(chan []anchorinfo.AnchorInfo, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		var anchors []anchorinfo.AnchorInfo

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)
		anchors = append(anchors, anchorinfo.AnchorInfo{CID: cid, WebCASURL: &url.URL{}})

		payload2 := subject.Payload{Namespace: namespace2, Version: 1, CoreIndex: "core2"}

		cid, _, err = anchorGraph.Add(buildCredential(payload2))
		require.NoError(t, err)
		anchors = append(anchors, anchorinfo.AnchorInfo{CID: cid})

		providers := &Providers{
			TxnProvider:            mockLedger{registerForAnchor: anchorCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		anchorCh <- anchors
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 1, tp.ProcessCallCount())
	})

	t.Run("success - process did (multiple, just create)", func(t *testing.T) {
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		var dids []string

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
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

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)
		dids = append(dids, cid+":"+did1, cid+":"+did2)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		didCh <- dids
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("success - process did with previous anchors", func(t *testing.T) {
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		did1 := "xyz"

		previousAnchors := make(map[string]string)
		previousAnchors[did1] = ""

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, hint, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		previousAnchors[did1] = hint + ":" + cid

		payload2 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "address", PreviousAnchors: previousAnchors}

		cid, _, err = anchorGraph.Add(buildCredential(payload2))
		require.NoError(t, err)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		didCh <- []string{cid + ":" + did1}
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("success - did and anchor", func(t *testing.T) {
		anchorCh := make(chan []anchorinfo.AnchorInfo, 100)
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		var dids []string
		var anchors []anchorinfo.AnchorInfo

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
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

		cid, hint, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		anchors = append(anchors, anchorinfo.AnchorInfo{CID: cid, WebCASURL: &url.URL{}, Hint: hint})
		dids = append(dids, cid+":"+did)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForAnchor: anchorCh, registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		anchorCh <- anchors
		didCh <- dids
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("error - transaction processor error", func(t *testing.T) {
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		var dids []string

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, "webcas:domain.com"),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
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

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)
		dids = append(dids, cid+":"+did1, cid+":"+did2)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		didCh <- dids
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 2, tp.ProcessCallCount())
	})

	t.Run("error - update did anchors error", func(t *testing.T) {
		anchorCh := make(chan []anchorinfo.AnchorInfo, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		var anchors []anchorinfo.AnchorInfo

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace1, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)
		anchors = append(anchors, anchorinfo.AnchorInfo{CID: cid, WebCASURL: &url.URL{}})

		payload2 := subject.Payload{Namespace: namespace2, Version: 1, CoreIndex: "core2"}

		cid, _, err = anchorGraph.Add(buildCredential(payload2))
		require.NoError(t, err)
		anchors = append(anchors, anchorinfo.AnchorInfo{CID: cid})

		providers := &Providers{
			TxnProvider:            mockLedger{registerForAnchor: anchorCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             &mockDidAnchor{Err: fmt.Errorf("did anchor error")},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		anchorCh <- anchors
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 1, tp.ProcessCallCount())
	})

	t.Run("error - cid not found", func(t *testing.T) {
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		didCh <- []string{"cid:did"}
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 0, tp.ProcessCallCount())
	})

	t.Run("error - invalid did format", func(t *testing.T) {
		didCh := make(chan []string, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		providers := &Providers{
			TxnProvider:            mockLedger{registerForDID: didCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
			DidAnchors:             memdidanchor.New(),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		didCh <- []string{"no-cid"}
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 0, tp.ProcessCallCount())
	})
}

type mockLedger struct {
	registerForAnchor chan []anchorinfo.AnchorInfo
	registerForDID    chan []string
}

func (m mockLedger) RegisterForAnchor() <-chan []anchorinfo.AnchorInfo {
	return m.registerForAnchor
}

func (m mockLedger) RegisterForDID() <-chan []string {
	return m.registerForDID
}

func buildCredential(payload subject.Payload) *verifiable.Credential {
	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: payload,
		Issuer: verifiable.Issuer{
			ID: "http://peer1.com",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	return vc
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}

type mockDidAnchor struct {
	Err error
}

func (m *mockDidAnchor) Put(_ []string, _ string) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

func (m *mockDidAnchor) Get(did []string) ([]string, error) {
	return []string{"cid"}, nil
}
