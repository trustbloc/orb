/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	apmocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	anchormocks "github.com/trustbloc/orb/pkg/anchor/mocks"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	resourceresolver "github.com/trustbloc/orb/pkg/resolver/resource"
	anchoreventstore "github.com/trustbloc/orb/pkg/store/anchorevent"
	"github.com/trustbloc/orb/pkg/store/anchoreventstatus"
	"github.com/trustbloc/orb/pkg/store/cas"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/vcsigner"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

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

	anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		AnchorGraph:      graph.New(&graph.Providers{}),
		DidAnchors:       memdidanchor.New(),
		AnchorBuilder:    &mockTxnBuilder{},
		AnchorEventStore: anchorEventStore,
	}

	t.Run("Success", func(t *testing.T) {
		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, &mocks.PubSub{},
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeReturns(nil, errExpected)

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, c)
	})
}

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
			Body:       ioutil.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	t.Run("success - no local witness configured, "+
		"witness needs to be resolved via HTTP", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false, resourceresolver.New(http.DefaultClient,
				nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - witness needs to be resolved via IPNS", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient,
				ipfs.New(testServer.URL, 5*time.Second, 0, &mocks.MetricsProvider{}),
			), &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: "ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			},
		}

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - local witness configured, sign with default witness is false", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("success - local witness", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		wit := &mockWitness{proofBytes: []byte(`{"proof": {"domain":"domain","created": "2021-02-23T19:36:07Z"}}`)}

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("error - status store error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: &mockstatusStore{Err: fmt.Errorf("status error")},
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to set 'in-process' status")
	})

	t.Run("Parse created time (error)", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		wit := &mockWitness{proofBytes: []byte(`{"proof": {"created": "021-02-23T:07Z"}}`)}

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			OpProcessor:      &mockOpProcessor{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			Witness:          wit,
			MonitoringSvc:    &mockMonitoring{},
			WitnessStore:     &mockWitnessStore{},
			ActivityStore:    &mockActivityStore{},
			AnchorEventStore: anchorEventStore,
			WFClient:         wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, nil, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse created: parsing time")
	})

	t.Run("error - failed to get witness list", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       &mockDidAnchor{},
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			MonitoringSvc:    &mockMonitoring{},
			WitnessStore:     &mockWitnessStore{},
			ActivityStore:    &mockActivityStore{},
			AnchorEventStore: anchorEventStore,
			OpProcessor:      &mockOpProcessor{Err: errors.New("operation processor error")},
			WFClient:         wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
			},
		}

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation processor error")
	})

	t.Run("error - build anchor event error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build anchor credential: sign error")
	})

	t.Run("error - anchor credential signing error", func(t *testing.T) {
		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{Err: fmt.Errorf("signer error")},
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.anchor", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)

		require.Contains(t, err.Error(), "signer error")
	})

	t.Run("error - local witness (monitoring error)", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
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
			AnchorEventStore:       anchorEventStore,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.anchor", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"monitoring error")
	})

	t.Run("error - local witness log error", func(t *testing.T) {
		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{},
			Witness:       &mockWitness{Err: fmt.Errorf("witness error")},
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.anchor", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Contains(t, err.Error(),
			"witness error")
	})

	t.Run("error - store anchor credential error", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrPut: fmt.Errorf("error put")},
		}

		anchorEventStoreWithErr, err := anchoreventstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStoreWithErr,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.anchor", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - store anchor credential error (local witness)", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrPut: fmt.Errorf("error put (local witness)")},
		}

		anchorEventStoreWithErr, err := anchoreventstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			Witness:          &mockWitness{},
			MonitoringSvc:    &mockMonitoring{},
			AnchorEventStore: anchorEventStoreWithErr,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
		require.NoError(t, err)

		var testServerURL string

		testServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err = w.Write(generateValidExampleHostMetaResponse(t, testServerURL))
				require.NoError(t, err)
			}))
		defer testServer.Close()

		testServerURL = testServer.URL

		err = c.WriteAnchor("1.anchor", nil,
			getOperationReferences(fmt.Sprintf("%s/services/orb", testServerURL)), 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put (local witness)")
	})

	t.Run("error - previous did anchor reference not found for non-create operations", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.WriteAnchor("anchor", nil, []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeUpdate}}, 0)
		require.Contains(t, err.Error(),
			"previous did anchor reference not found for update operation for did[did:method:abc]")
	})

	t.Run("error - publish anchor", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		publisher := &anchormocks.AnchorPublisher{}
		publisher.PublishAnchorReturns(errors.New("injected publisher error"))

		c, err := New(namespace, apServiceIRI, casIRI, providers, publisher, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(http.DefaultClient, nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})

	t.Run("error - fail to resolve anchor origin via IPNS (IPFS node not reachable)", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false,
			resourceresolver.New(nil, ipfs.New("SomeIPFSNodeURL", time.Second, 0, &mocks.MetricsProvider{})),
			&mocks.MetricsProvider{})
		require.NoError(t, err)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-4",
				Type:         operation.TypeCreate,
				AnchorOrigin: "ipns://k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek",
			},
		}

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), `failed to get host-meta document via IPNS: failed to read from IPNS: cat IPFS `+
			`of CID [/ipns/k51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mhl7uyhdre8ateqek/.well-known/host-meta.json]: `+
			`Post "http://SomeIPFSNodeURL/api/v0/cat?arg=%2Fipns%2Fk51qzi5uqu5dgjceyz40t6xfnae8jqn5z17ojojggzwz2mh`+
			`l7uyhdre8ateqek%2F.well-known%2Fhost-meta.json":`)
	})

	t.Run("error - no witnesses configured", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			WitnessPolicy:          witnessPolicy,
			ProofHandler:           servicemocks.NewProofHandler(),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false, resourceresolver.New(http.DefaultClient,
				nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.Error(t, err)
		require.True(t, orberrors.IsTransient(err))
		require.Contains(t, err.Error(), "no witnesses are provided")
	})

	t.Run("success - no witnesses required", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
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
			AnchorEventStore:       anchorEventStore,
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
			WitnessPolicy:          &mockWitnessPolicy{},
			ProofHandler:           servicemocks.NewProofHandler(),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, false, resourceresolver.New(http.DefaultClient,
				nil), &mocks.MetricsProvider{})
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

		err = c.WriteAnchor("1.anchor", nil, opRefs, 0)
		require.NoError(t, err)
	})
}

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
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			WitnessStore:     &mockWitnessStore{},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		require.NoError(t, c.handle(anchorEvent))
	})

	t.Run("error - add anchor credential to txn graph error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:      &mockAnchorGraph{Err: errors.New("txn graph error")},
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		err = c.handle(anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add witnessed anchor event")
	})

	t.Run("error - add anchor credential cid to did anchors error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       &mockDidAnchor{Err: errors.New("did references error")},
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			WitnessStore:     &mockWitnessStore{},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		errExpected := errors.New("anchor publisher error")

		anchorPublisher := &anchormocks.AnchorPublisher{}
		anchorPublisher.PublishAnchorReturns(errExpected)

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorPublisher, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		err = c.handle(anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - outbox error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{Err: errors.New("outbox error")},
			AnchorEventStore: anchorEventStore,
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
			WitnessStore:     &mockWitnessStore{},
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		err = c.handle(anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "post create activity for anchor event")
		require.False(t, orberrors.IsTransient(err))
	})

	t.Run("error - delete transient data from witness store error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			WitnessStore:     &mockWitnessStore{DeleteErr: fmt.Errorf("delete error")},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		require.NoError(t, c.handle(anchorEvent))
	})

	t.Run("error - delete anchor event error (transient store - log only)", func(t *testing.T) {
		storeProviderWithErr := &mockstore.Provider{
			OpenStoreReturn: &mockstore.Store{ErrDelete: fmt.Errorf("error delete")},
		}

		anchorEventStoreWithErr, err := anchoreventstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStoreWithErr,
			WitnessStore:     &mockWitnessStore{},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providersWithErr, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		require.NoError(t, c.handle(anchorEvent))
	})

	t.Run("error - parse verifiable credential from anchor event error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore, err := mem.NewProvider().OpenStore("verifiable")
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			WitnessStore:     &mockWitnessStore{},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEventInvalidWitness), anchorEvent))

		err = c.handle(anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer is required")
		require.False(t, orberrors.IsTransient(err))
	})

	t.Run("error - store to verifiable credential store", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStore := &storemocks.Store{}
		vcStore.PutReturns(fmt.Errorf("anchor event store error"))

		providers := &Providers{
			AnchorGraph:      anchorGraph,
			DidAnchors:       memdidanchor.New(),
			AnchorBuilder:    &mockTxnBuilder{},
			Outbox:           &mockOutbox{},
			Signer:           &mockSigner{},
			AnchorEventStore: anchorEventStore,
			WitnessStore:     &mockWitnessStore{},
			VCStore:          vcStore,
			DocumentLoader:   testutil.GetLoader(t),
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		anchorEvent := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

		err = c.handle(anchorEvent)
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
			Body:       ioutil.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	anchorEvent := &vocab.AnchorEventType{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

	t.Run("success", func(t *testing.T) {
		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			Outbox:                 &mockOutbox{},
			WitnessStore:           &mockWitnessStore{},
			WitnessPolicy:          &mockWitnessPolicy{},
			ActivityStore:          &mockActivityStore{},
			AnchorEventStatusStore: statusStore,
			WFClient:               wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
		require.NoError(t, err)
	})

	t.Run("error - get witnesses URIs error", func(t *testing.T) {
		providers := &Providers{
			Outbox: &mockOutbox{},
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{":xyz"})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - webfinger client error (batch and system witness)", func(t *testing.T) {
		wfClientWithErr := wfclient.New(wfclient.WithHTTPClient(
			httpMock(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString("internal server error")),
					StatusCode: http.StatusInternalServerError,
				}, nil
			})))

		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{},
			WFClient:      wfClientWithErr,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		// test error for batch witness
		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to resolve WebFinger resource[https://abc.com/vct]: received unexpected status code. URL [https://abc.com/.well-known/webfinger?resource=https://abc.com/vct], status code [500], response body [internal server error]") //nolint:lll

		// test error for system witness (no batch witnesses)
		err = c.postOfferActivity(anchorEvent, nil, []string{})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to resolve WebFinger resource[http://orb.domain1.com/vct]: received unexpected status code. URL [http://orb.domain1.com/.well-known/webfinger?resource=http://orb.domain1.com/vct], status code [500], response body [internal server error]") //nolint:lll
	})

	t.Run("error - activity store error", func(t *testing.T) {
		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{Err: fmt.Errorf("activity store error")},
			WFClient:      wfClient,
		}

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, nil, []string{"https://abc.com/services/orb"})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness,
			resourceresolver.New(http.DefaultClient, nil, resourceresolver.WithCacheLifetime(0)),
			&mocks.MetricsProvider{})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
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

		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
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
			Body:       ioutil.NopCloser(bytes.NewBufferString(webfingerPayload)),
			StatusCode: http.StatusOK,
		}, nil
	})

	wfClient := wfclient.New(wfclient.WithHTTPClient(wfHTTPClient))

	c, err := New(namespace, apServiceIRI, nil, &Providers{WFClient: wfClient}, &anchormocks.AnchorPublisher{}, ps,
		testMaxWitnessDelay, true, nil, &mocks.MetricsProvider{})
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
		c, err := New(namespace, apServiceIRI, casIRI, providers, &anchormocks.AnchorPublisher{}, ps,
			testMaxWitnessDelay, signWithLocalWitness, nil, &mocks.MetricsProvider{})
		require.NoError(t, err)

		more, entries := c.Read(-1)
		require.False(t, more)
		require.Empty(t, entries)
	})
}

type mockTxnBuilder struct {
	Err error
}

func (m *mockTxnBuilder) Build(anchorHashlink string) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return &verifiable.Credential{Subject: &builder.CredentialSubject{ID: anchorHashlink}}, nil
}

type mockAnchorGraph struct {
	Err error
}

func (m *mockAnchorGraph) Add(eventType *vocab.AnchorEventType) (string, error) {
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

func (m *mockOpProcessor) Resolve(uniqueSuffix string, _ ...*operation.AnchoredOperation) (*protocol.ResolutionModel, error) { //nolint:lll
	if m.Err != nil {
		return nil, m.Err
	}

	return m.Map[uniqueSuffix], nil
}

type mockOutbox struct {
	Err error
}

func (m *mockOutbox) Post(activity *vocab.ActivityType, _ ...*url.URL) (*url.URL, error) {
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

func (a *mockActivityStore) QueryReferences(refType spi.ReferenceType, query *spi.Criteria, opts ...spi.QueryOpt) (spi.ReferenceIterator, error) { // nolint: lll
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

//nolint: lll
const jsonAnchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "index": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
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

//nolint: lll
const jsonAnchorEventInvalidWitness = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "index": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
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
