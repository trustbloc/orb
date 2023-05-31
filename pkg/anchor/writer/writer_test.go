/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	writermocks "github.com/trustbloc/orb/pkg/anchor/writer/mocks"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
	anchorlinkstore "github.com/trustbloc/orb/pkg/store/anchorlink"
	"github.com/trustbloc/orb/pkg/store/anchorstatus"
	"github.com/trustbloc/orb/pkg/store/cas"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/vcsigner"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

//go:generate counterfeiter -o ./mocks/webfingerclient.gen.go --fake-name WebFingerCLient . webfingerClient

const (
	namespace = "did:orb"

	testDID = "did:method:abc"

	activityPubURL = "http://localhost/services/orb"
	casURL         = "http://localhost/cas"

	testMaxWitnessDelay = 600 * time.Second

	signWithLocalWitness = true

	webfingerPayload = `{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct-v1"}}`
)

func TestNew(t *testing.T) {
	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
	require.NoError(t, err)

	providers := &Providers{
		AnchorGraph:     graph.New(&graph.Providers{}),
		DidAnchors:      memdidanchor.New(),
		AnchorBuilder:   &mockTxnBuilder{},
		AnchorLinkStore: anchorEventStore,
	}

	t.Run("Success", func(t *testing.T) {
		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, &mocks.PubSub{}, testMaxWitnessDelay,
			signWithLocalWitness, nil, 5, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeWithOptsReturns(nil, errExpected)

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			nil, 5, &mocks.MetricsProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, c)
	})
}

//nolint:maintidx
func TestWriter_WriteAnchor(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	casClient, err := cas.New(mem.NewProvider(), casURL, nil, &mocks.MetricsProvider{}, 100)

	require.NoError(t, err)

	graphProviders := &graph.Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
					transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
				wfclient.New(), "https"), &mocks.MetricsProvider{}),
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	anchorGraph := graph.New(graphProviders)

	wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	t.Run("success - no local witness configured, "+
		"witness needs to be resolved via HTTP", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - witness needs to be resolved via IPNS", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient,
				ipfs.New(testServer.URL, 5*time.Second, 0, &mocks.MetricsProvider{}),
				&mocks.DomainResolver{},
			), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: "ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - local witness configured, sign with default witness is false", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			Witness:                &mockWitness{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - local witness", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		wit := &mockWitness{proofBytes: []byte(`{"proof": {"domain":"domain","created": "2021-02-23T19:36:07Z"}}`)}

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			Witness:                wit,
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("error - status store error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		wit := &mockWitness{proofBytes: []byte(`{"proof": {"domain":"domain","created": "2021-02-23T19:36:07Z"}}`)}

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			Witness:                wit,
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: &mockstatusStore{Err: fmt.Errorf("status error")},
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to set 'in-process' status")
	})

	t.Run("Parse created time (error)", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		wit := &mockWitness{proofBytes: []byte(`{"proof": {"created": "021-02-23T:07Z"}}`)}

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			OpProcessor:       &mockOpProcessor{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			Witness:           wit,
			MonitoringSvc:     &mockMonitoring{},
			WitnessStore:      &mockWitnessStore{},
			ActivityStore:     &mockActivityStore{},
			AnchorLinkStore:   anchorEventStore,
			WFClient:          wfClient,
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			nil, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse created: parsing time")
	})

	t.Run("error - failed to get witness list", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        &mockDidAnchor{},
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			MonitoringSvc:     &mockMonitoring{},
			WitnessStore:      &mockWitnessStore{},
			ActivityStore:     &mockActivityStore{},
			AnchorLinkStore:   anchorEventStore,
			OpProcessor:       &mockOpProcessor{Err: errors.New("operation processor error")},
			WFClient:          wfClient,
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			nil, 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation processor error")
	})

	t.Run("error - build anchor event error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{Err: errors.New("sign error")},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			Witness:                &mockWitness{},
			WitnessStore:           &mockWitnessStore{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build anchor credential: sign error")
	})

	t.Run("error - anchor credential signing error", func(t *testing.T) {
		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{Err: fmt.Errorf("signer error")},
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)

		require.Contains(t, err.Error(), "signer error")
	})

	t.Run("error - local witness (monitoring error)", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{},
			OpProcessor:   &mockOpProcessor{},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{},
			Witness: &mockWitness{
				proofBytes: []byte(`{"proof": {"domain":"domain","created": "2021-02-23T19:36:07Z"}}`),
			},
			AnchorEventStatusStore: &mockstatusStore{},
			WitnessStore:           &mockWitnessStore{},
			ActivityStore:          &mockActivityStore{},
			MonitoringSvc:          &mockMonitoring{Err: fmt.Errorf("monitoring error")},
			AnchorLinkStore:        anchorEventStore,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"monitoring error")
	})

	t.Run("error - local witness log error", func(t *testing.T) {
		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			Witness:           &mockWitness{Err: fmt.Errorf("witness error")},
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Contains(t, err.Error(),
			"witness error")
	})

	t.Run("error - store anchor credential error", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrPut: fmt.Errorf("error put")},
		}

		anchorEventStoreWithErr, err := anchorlinkstore.New(storeProviderWithErr)
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStoreWithErr,
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - store anchor credential error (local witness)", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrPut: fmt.Errorf("error put (local witness)")},
		}

		anchorEventStoreWithErr, err := anchorlinkstore.New(storeProviderWithErr)
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			Witness:           &mockWitness{},
			MonitoringSvc:     &mockMonitoring{},
			AnchorLinkStore:   anchorEventStoreWithErr,
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put (local witness)")
	})

	t.Run("error - previous did anchor reference not found for non-create operations", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			nil, 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.WriteAnchor("anchor", nil, []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeUpdate}}, 0)
		require.Contains(t, err.Error(),
			"previous did anchor reference not found for update operation for did[did:method:abc]")
	})

	t.Run("error - publish anchor", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		publisher := &anchormocks.AnchorPublisher{}
		publisher.PublishAnchorReturns(errors.New("injected publisher error"))

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers, publisher, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServerURL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("error - fail to resolve anchor origin via IPNS (IPFS node not reachable)", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			ActivityStore:          &mockActivityStore{},
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(nil, ipfs.New("SomeIPFSNodeURL", time.Second, 0, &mocks.MetricsProvider{}),
				&mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-4",
				Type:         operation.TypeCreate,
				AnchorOrigin: "ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			`failed to get host-meta document from [ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek]:`+
				` failed to read from IPNS: cat IPFS `+
				`of CID [/ipns/k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek/.well-known/host-meta.json]: `+
				`Post "http://SomeIPFSNodeURL/api/v0/cat?arg=%2Fipns%2Fk51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mh`+
				`l7uyhdre8ateqek%2F.well-known%2Fhost-meta.json":`)
	})

	t.Run("error - no witnesses configured", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		activityStore := memstore.New("")

		witnessPolicy := &mockWitnessPolicy{}
		witnessPolicy.Err = orberrors.NewTransientf("no witnesses are provided")

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			ActivityStore:          activityStore,
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			WitnessPolicy:          witnessPolicy,
			ProofHandler:           servicemocks.NewProofHandler(),
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay,
			false, resourceresolver.New(http.DefaultClient,
				nil, &mocks.DomainResolver{}), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		hostMetaResponse := discoveryrest.JRD{
			Subject:    "",
			Properties: nil,
			Links: []discoveryrest.Link{
				{
					Type: discoveryrest.ActivityJSONType,
					Href: apServiceIRI.String(),
				},
			},
		}

		hostMetaResponseBytes, err := json.Marshal(hostMetaResponse)
		require.NoError(t, err)

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(hostMetaResponseBytes)
				require.NoError(t, err)
			}))
		defer testServer.Close()

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServer.URL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.Error(t, err)
		require.True(t, orberrors.IsTransient(err))
		require.Contains(t, err.Error(), "no witnesses are provided")
	})

	t.Run("success - no witnesses required", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		activityStore := memstore.New("")

		providers := &Providers{
			AnchorGraph:            anchorGraph,
			DidAnchors:             memdidanchor.New(),
			AnchorBuilder:          &mockTxnBuilder{},
			OpProcessor:            &mockOpProcessor{},
			Outbox:                 &mockOutbox{},
			Signer:                 &mockSigner{},
			MonitoringSvc:          &mockMonitoring{},
			WitnessStore:           &mockWitnessStore{},
			ActivityStore:          activityStore,
			AnchorLinkStore:        anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			WitnessPolicy:          &mockWitnessPolicy{},
			ProofHandler:           servicemocks.NewProofHandler(),
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil, &mocks.DomainResolver{}),
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		hostMetaResponse := discoveryrest.JRD{
			Subject:    "",
			Properties: nil,
			Links: []discoveryrest.Link{
				{
					Type: discoveryrest.ActivityJSONType,
					Href: apServiceIRI.String(),
				},
			},
		}

		hostMetaResponseBytes, err := json.Marshal(hostMetaResponse)
		require.NoError(t, err)

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(hostMetaResponseBytes)
				require.NoError(t, err)
			}))
		defer testServer.Close()

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: fmt.Sprintf("%s/services/orb", testServer.URL),
			},
		}

		err = c.WriteAnchor("1.hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw", nil, opRefs, 0)
		require.NoError(t, err)
	})
}

//nolint:maintidx
func TestWriter_handle(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	casClient, err := cas.New(mem.NewProvider(), casURL, nil, &mocks.MetricsProvider{}, 0)

	require.NoError(t, err)

	graphProviders := &graph.Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
					transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
				wfclient.New(), "https"), &mocks.MetricsProvider{}),
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	anchorGraph := graph.New(graphProviders)

	t.Run("success", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			WitnessStore:      &mockWitnessStore{},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		require.NoError(t, c.handle(context.Background(), anchorLinkset))
	})

	t.Run("error - add anchor credential to txn graph error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:       &mockAnchorGraph{Err: errors.New("txn graph error")},
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			nil, 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		err = c.handle(context.Background(), anchorLinkset)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add witnessed anchor")
	})

	t.Run("error - add anchor credential cid to did anchors error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        &mockDidAnchor{Err: errors.New("did references error")},
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			WitnessStore:      &mockWitnessStore{},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		errExpected := errors.New("anchor publisher error")

		anchorPublisher := &anchormocks.AnchorPublisher{}
		anchorPublisher.PublishAnchorReturns(errExpected)

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			anchorPublisher, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		err = c.handle(context.Background(), anchorLinkset)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - outbox error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{Err: errors.New("outbox error")},
			AnchorLinkStore:   anchorEventStore,
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			WitnessStore:      &mockWitnessStore{},
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		err = c.handle(context.Background(), anchorLinkset)
		require.Error(t, err)
		require.Contains(t, err.Error(), "post create activity for anchor")
		require.False(t, orberrors.IsTransient(err))
	})

	t.Run("error - delete transient data from witness store error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			WitnessStore:      &mockWitnessStore{DeleteErr: fmt.Errorf("delete error")},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		require.NoError(t, c.handle(context.Background(), anchorLinkset))
	})

	t.Run("error - delete anchor event error (transient store - log only)", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrDelete: fmt.Errorf("error delete")},
		}

		anchorEventStoreWithErr, err := anchorlinkstore.New(storeProviderWithErr)
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStoreWithErr,
			WitnessStore:      &mockWitnessStore{},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providersWithErr,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			nil, 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		require.NoError(t, c.handle(context.Background(), anchorLinkset))
	})

	t.Run("error - parse verifiable credential from anchor event error", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			WitnessStore:      &mockWitnessStore{},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinksetInvalidReply), anchorLinkset))

		err = c.handle(context.Background(), anchorLinkset)
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
		require.False(t, orberrors.IsTransient(err))
	})

	t.Run("error - store to verifiable credential store", func(t *testing.T) {
		anchorEventStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		vcStore := &storemocks.Store{}
		vcStore.PutReturns(fmt.Errorf("anchor event store error"))

		providers := &Providers{
			AnchorGraph:       anchorGraph,
			DidAnchors:        memdidanchor.New(),
			AnchorBuilder:     &mockTxnBuilder{},
			Outbox:            &mockOutbox{},
			Signer:            &mockSigner{},
			AnchorLinkStore:   anchorEventStore,
			WitnessStore:      &mockWitnessStore{},
			VCStore:           vcStore,
			DocumentLoader:    testutil.GetLoader(t),
			GeneratorRegistry: generator.NewRegistry(),
			AnchorLinkBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorLinkset := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

		err = c.handle(context.Background(), anchorLinkset)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store vc")
		require.False(t, orberrors.IsTransient(err))
	})
}

func TestWriter_postOfferActivity(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	anchorLinkset := &linkset.Linkset{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

	anchorLink := anchorLinkset.Link()
	require.NotNil(t, anchorLink)

	t.Run("success", func(t *testing.T) {
		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			Outbox:                 &mockOutbox{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			GeneratorRegistry:      generator.NewRegistry(),
			AnchorLinkBuilder:      anchorlinkset.NewBuilder(generator.NewRegistry()),
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
		require.NoError(t, err)
	})

	t.Run("error - get witnesses URIs error", func(t *testing.T) {
		providers := &Providers{
			Outbox: &mockOutbox{},
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{":xyz"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})

	t.Run("error - witness proof store error", func(t *testing.T) {
		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{PutErr: fmt.Errorf("witness store error")},
			WitnessPolicy: &mockWitnessPolicy{},
			ActivityStore: &mockActivityStore{},
			WFClient:      wfClient,
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("webfinger client error (batch and system witness) - ignores witnesses for domains that are down",
		func(t *testing.T) {
			wfClientWithErr := &writermocks.WebFingerCLient{}
			wfClientWithErr.HasSupportedLedgerTypeReturnsOnCall(0, false,
				errors.New("injected WebFinger client error"))
			wfClientWithErr.HasSupportedLedgerTypeReturnsOnCall(1, true, nil)
			wfClientWithErr.HasSupportedLedgerTypeReturnsOnCall(3, false,
				errors.New("injected WebFinger client error"))
			wfClientWithErr.HasSupportedLedgerTypeReturnsOnCall(4, true, nil)

			statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetTaskMgr(t), testutil.GetExpiryService(t), time.Minute)
			require.NoError(t, err)

			providers := &Providers{
				Outbox:                 &mockOutbox{},
				WitnessStore:           &mockWitnessStore{},
				WitnessPolicy:          &mockWitnessPolicy{},
				ActivityStore:          &mockActivityStore{},
				WFClient:               wfClientWithErr,
				AnchorEventStatusStore: statusStore,
			}

			c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
				&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
				5, &mocks.MetricsProvider{})
			require.NoError(t, err)

			// test error for batch witness
			err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
			require.NoError(t, err)

			// test error for system witness (no batch witnesses)
			err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{})
			require.NoError(t, err)
		},
	)

	t.Run("error - activity store error", func(t *testing.T) {
		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{Err: fmt.Errorf("activity store error")},
			WFClient:      wfClient,
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to query references for system witnesses: activity store error")
	})

	t.Run("error - post offer to outbox error", func(t *testing.T) {
		providers := &Providers{
			Outbox:                 &mockOutbox{Err: fmt.Errorf("outbox error")},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorEventStatusStore: &mockstatusStore{},
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbox error")
	})

	t.Run("error - witness selection error", func(t *testing.T) {
		providers := &Providers{
			Outbox:                 &mockOutbox{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{Err: fmt.Errorf("witness selection error")},
			ActivityStore:          &mockActivityStore{},
			AnchorEventStatusStore: &mockstatusStore{},
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(context.Background(), anchorLink, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get witnesses: select witnesses: witness selection error")
	})
}

func TestWriter_getWitnesses(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		var numTimesMockServerHandlerHit int

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if numTimesMockServerHandlerHit == 5 {
					// Ensure that one of the witnesses returned is a duplicate of another one.
					_, err = w.Write(generateValidExampleHostMetaResponse(t, fmt.Sprintf("%s/4", testServerURL)))
					require.NoError(t, err)
				} else {
					_, err = w.Write(generateValidExampleHostMetaResponse(t, fmt.Sprintf("%s/%d", testServerURL,
						numTimesMockServerHandlerHit)))
					require.NoError(t, err)
				}

				numTimesMockServerHandlerHit++
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		testAnchorOrigin := fmt.Sprintf("%s/services/orb", testServerURL)

		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: testAnchorOrigin},
			"did-2": {AnchorOrigin: testAnchorOrigin},
			"did-3": {AnchorOrigin: testAnchorOrigin},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(
				http.DefaultClient, nil, &mocks.DomainResolver{},
				resourceresolver.WithCacheLifetime(0),
			), 5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
				AnchorOrigin: testAnchorOrigin,
			},
			{
				UniqueSuffix: "did-2",
				Type:         operation.TypeRecover,
				AnchorOrigin: testAnchorOrigin,
			},
			{
				UniqueSuffix: "did-3",
				Type:         operation.TypeDeactivate,
				AnchorOrigin: testAnchorOrigin,
			},
			{
				UniqueSuffix: "did-4",
				Type:         operation.TypeCreate,
				AnchorOrigin: testAnchorOrigin,
			},
			{
				UniqueSuffix: "did-5",
				Type:         operation.TypeCreate,
				AnchorOrigin: testAnchorOrigin,
			},
			{
				UniqueSuffix: "did-6",
				Type:         operation.TypeCreate,
				AnchorOrigin: testAnchorOrigin, // test re-use same origin (this will be the same as the one above)
			},
		}

		witnesses, err := c.getWitnessesFromBatchOperations(opRefs)
		require.NoError(t, err)
		require.Equal(t, 5, len(witnesses))

		expectedWitnessTemplate := "%s/%d/services/orb"

		expected := []string{
			fmt.Sprintf(expectedWitnessTemplate, testServerURL, 0),
			fmt.Sprintf(expectedWitnessTemplate, testServerURL, 1),
			fmt.Sprintf(expectedWitnessTemplate, testServerURL, 2),
			fmt.Sprintf(expectedWitnessTemplate, testServerURL, 3),
			fmt.Sprintf(expectedWitnessTemplate, testServerURL, 4),
		}
		require.Equal(t, expected, witnesses)
	})

	t.Run("error - operation type not supported", func(t *testing.T) {
		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: "origin-1.com"},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         "invalid",
			},
		}

		witnesses, err := c.getWitnessesFromBatchOperations(opRefs)
		require.Error(t, err)
		require.Nil(t, witnesses)
		require.Contains(t, err.Error(), "operation type 'invalid' not supported for assembling witness list")
	})

	t.Run("error - unexpected interface for anchor origin", func(t *testing.T) {
		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: 0},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
				AnchorOrigin: 10,
			},
		}

		witnesses, err := c.getWitnessesFromBatchOperations(opRefs)
		require.Error(t, err)
		require.Nil(t, witnesses)
		require.Contains(t, err.Error(), "unexpected interface 'int' for anchor origin")
	})
}

func TestWriter_getBatchWitnessesIRI(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	wfHTTPClient := httpMock(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	c, err := New(namespace, apServiceIRI, apServiceIRI, nil, vocab.JSONMediaType, &Providers{WFClient: wfClient},
		&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, true, nil,
		5, &mocks.MetricsProvider{})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		witnesses := []string{"http://origin-1.com", "http://origin-2.com"}

		witnessesIRI, err := c.getBatchWitnesses(witnesses)
		require.NoError(t, err)

		// two from witness list
		require.Equal(t, 2, len(witnessesIRI))
	})

	t.Run("success - exclude current domain from witness list", func(t *testing.T) {
		witnesses := []string{activityPubURL}

		witnessesIRI, err := c.getBatchWitnesses(witnesses)
		require.NoError(t, err)

		require.Equal(t, 0, len(witnessesIRI))
	})

	t.Run("error - invalid url", func(t *testing.T) {
		witnesses := []string{":xyz"}

		witnessesIRI, err := c.getBatchWitnesses(witnesses)
		require.Error(t, err)
		require.Nil(t, witnessesIRI)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})
}

func TestWriter_Read(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	casClient, err := cas.New(mem.NewProvider(), casURL, nil, &mocks.MetricsProvider{}, 0)

	require.NoError(t, err)

	graphProviders := &graph.Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				transport.New(&http.Client{}, testutil.MustParseURL("https://example.com/keys/public-key"),
					transport.DefaultSigner(), transport.DefaultSigner(), &apclientmocks.AuthTokenMgr{}),
				wfclient.New(), "https"), &mocks.MetricsProvider{}),
	}

	providers := &Providers{
		AnchorGraph: graph.New(graphProviders),
		DidAnchors:  memdidanchor.New(),
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		c, err := New(namespace, apServiceIRI, apServiceIRI, casIRI, vocab.JSONMediaType, providers,
			&anchormocks.AnchorPublisher{}, ps, testMaxWitnessDelay, signWithLocalWitness, nil,
			5, &mocks.MetricsProvider{})
		require.NoError(t, err)

		more, entries := c.Read(-1)
		require.False(t, more)
		require.Empty(t, entries)
	})
}

type mockTxnBuilder struct {
	Err error
}

func (m *mockTxnBuilder) Build(profile *url.URL, anchorHashlink, coreIndexHashlink string,
	_ []string,
) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return &verifiable.Credential{Subject: &builder.CredentialSubject{
		HRef:    anchorHashlink,
		Type:    []string{"AnchorLink"},
		Anchor:  coreIndexHashlink,
		Profile: profile.String(),
		Rel:     "linkset",
	}}, nil
}

type mockAnchorGraph struct {
	Err error
}

func (m *mockAnchorGraph) Add(anchorLink *linkset.Linkset) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}

	return "cid", nil
}

type mockDidAnchor struct {
	Err error
}

func (m *mockDidAnchor) GetBulk(did []string) ([]string, error) {
	return []string{"hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"}, nil
}

type mockOpProcessor struct {
	Err error
	Map map[string]*protocol.ResolutionModel
}

func (m *mockOpProcessor) Resolve(uniqueSuffix string, _ ...document.ResolutionOption) (*protocol.ResolutionModel, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.Map[uniqueSuffix], nil
}

type mockOutbox struct {
	Err error
}

func (m *mockOutbox) Post(ctx context.Context, activity *vocab.ActivityType, exclude ...*url.URL) (*url.URL, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return activity.ID().URL(), nil
}

type mockSigner struct {
	Err error
}

func (m *mockSigner) Sign(vc *verifiable.Credential, opts ...vcsigner.Opt) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return vc, nil
}

func (m *mockSigner) Context() []string {
	return []string{}
}

type mockWitness struct {
	proofBytes []byte
	Err        error
}

func (w *mockWitness) Witness(anchorCred []byte) ([]byte, error) {
	if w.Err != nil {
		return nil, w.Err
	}

	if len(w.proofBytes) != 0 {
		return w.proofBytes, nil
	}

	return anchorCred, nil
}

type mockMonitoring struct {
	Err error
}

func (m *mockMonitoring) Watch(_ *verifiable.Credential, _ time.Time, _ string, _ time.Time) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

type mockActivityStore struct {
	Err error
}

func (a *mockActivityStore) QueryReferences(spi.ReferenceType, *spi.Criteria, ...spi.QueryOpt) (spi.ReferenceIterator, error) {
	if a.Err != nil {
		return nil, a.Err
	}

	systemWitnessIRI, err := url.Parse("http://orb.domain1.com/services/orb")
	if err != nil {
		return nil, err
	}

	iter := &apmocks.ReferenceIterator{}

	iter.NextReturnsOnCall(0, systemWitnessIRI, nil)
	iter.NextReturnsOnCall(1, nil, spi.ErrNotFound)

	return iter, nil
}

type mockWitnessStore struct {
	PutErr    error
	DeleteErr error
}

func (w *mockWitnessStore) Put(vcID string, witnesses []*proof.Witness) error {
	if w.PutErr != nil {
		return w.PutErr
	}

	return nil
}

func (w *mockWitnessStore) Delete(vcID string) error {
	if w.DeleteErr != nil {
		return w.DeleteErr
	}

	return nil
}

type mockstatusStore struct {
	Err error
}

func (ss *mockstatusStore) AddStatus(vcID string, status proof.AnchorIndexStatus) error {
	if ss.Err != nil {
		return ss.Err
	}

	return nil
}

func getOperationReferences(anchorOrigin string) []*operation.Reference {
	return []*operation.Reference{
		{
			UniqueSuffix: "did-1",
			Type:         operation.TypeCreate,
			AnchorOrigin: anchorOrigin,
		},
	}
}

func generateValidExampleHostMetaResponse(t *testing.T, hostnameInResponse string) []byte {
	t.Helper()

	hostMetaResponse := discoveryrest.JRD{
		Subject:    "",
		Properties: nil,
		Links: []discoveryrest.Link{
			{
				Type: discoveryrest.ActivityJSONType,
				Href: fmt.Sprintf("%s/services/orb", hostnameInResponse),
			},
		},
	}

	hostMetaResponseBytes, err := json.Marshal(hostMetaResponse)
	require.NoError(t, err)

	return hostMetaResponseBytes
}

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}

type mockWitnessPolicy struct {
	Witnesses []*proof.Witness
	Err       error
}

func (wp *mockWitnessPolicy) Select(witnesses []*proof.Witness, _ ...*proof.Witness) ([]*proof.Witness, error) {
	if wp.Err != nil {
		return nil, wp.Err
	}

	if wp.Witnesses != nil {
		return wp.Witnesses, nil
	}

	return witnesses, nil
}

const jsonAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiAwzxyCuljGunAZosU5wzHp6_GKaR8-vbm_Q7-igvqG4A",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiChdZc6rYMIF6dkfSSqjpIeIiIugYwvO-RXfsa6VgvN9w%22%2C%22author%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiDpA73ihhjK8SpcKhIRu0tOR1b-LR9B-ACeflnJyStFxQ%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAwzxyCuljGunAZosU5wzHp6_GKaR8-vbm_Q7-igvqG4A%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiChdZc6rYMIF6dkfSSqjpIeIiIugYwvO-RXfsa6VgvN9w%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQ2hkWmM2cllNSUY2ZGtmU1NxanBJZUlpSXVnWXd2Ty1SWGZzYTZWZ3ZOOXd4QmlwZnM6Ly9iYWZrcmVpZmJvd2x0dmxtZGJhbDJvemQ1ZXN2aTVlcTZlaXJjNWFtbWY0NTZpdjM2eTI1Zm1jNm42NA%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiChdZc6rYMIF6dkfSSqjpIeIiIugYwvO-RXfsa6VgvN9w%22%2C%22href%22%3A%22hl%3AuEiAwzxyCuljGunAZosU5wzHp6_GKaR8-vbm_Q7-igvqG4A%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22rel%22%3A%22linkset%22%2C%22type%22%3A%5B%22AnchorLink%22%5D%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fef209ef6-a635-4c2d-8984-341e8749f1dd%22%2C%22issuanceDate%22%3A%222022-08-25T15%3A13%3A31.967946894Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%7B%22created%22%3A%222022-08-25T15%3A13%3A31.977Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z5ubHgQk24qJDnSJ7TZdWhsRa1SJQw6k8VpGTs4pvC1zzonoyP6UmbbdAmxd2nczV9kFQ4xhWBoEjBxwwGiF1jszB%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23cFDdR4w4CjaIVu42yUPmNdpmxdFtLUnyMUgh5NaZ6WE%22%7D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

const jsonAnchorLinksetInvalidReply = `{
  "linkset": [
    {
      "anchor": "hl:uEiAr_xUtbeoALO4iKvN5eIWjqUmIO35wFEPTTzjOaSYgUA",
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "author": [
        {
          "href": "did:web:orb.domain2.com:services:orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiDN_w5UTmfhZa-k9AwutAxw4qPSRPbxpwi9Ik9Tqh3wkg%22%2C%22author%22%3A%5B%7B%22href%22%3A%22did%3Aweb%3Aorb.domain2.com%3Aservices%3Aorb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiCHYLNrOLv5cYSVrTEtzSvOI3uQPukFzxsQMjfy8r25fA%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAr_xUtbeoALO4iKvN5eIWjqUmIO35wFEPTTzjOaSYgUA%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiDN_w5UTmfhZa-k9AwutAxw4qPSRPbxpwi9Ik9Tqh3wkg%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpRE5fdzVVVG1maFphLWs5QXd1dEF4dzRxUFNSUGJ4cHdpOUlrOVRxaDN3a2c%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiDN_w5UTmfhZa-k9AwutAxw4qPSRPbxpwi9Ik9Tqh3wkg%22%2C%22id%22%3A%22hl%3AuEiAr_xUtbeoALO4iKvN5eIWjqUmIO35wFEPTTzjOaSYgUA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain2.com%2Fvc%2F654bea3b-63a6-4ec7-a73f-0b63c083acc2%22%2C%22issuanceDate%22%3A%222022-08-24T13%3A12%3A21.317143941Z%22%2C%22proof%22%3A%7B%22created%22%3A%222022-08-24T13%3A12%3A21.318445635Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z2cWVavmjqJhjAYV1dYzaKLegq3y4wUgZgDvMJiHFdvyRhBgZQ5fqXyf3RKddS5GsBpsPg1GmEorALAqLkjPNXpWK%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23ArGfVFUvJOYE79EO_yJOwgCCH56247AZ7KjK4NIUkug%22%7D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
