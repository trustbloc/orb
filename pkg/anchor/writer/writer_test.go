/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/didanchor/memdidanchor"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

const (
	namespace = "did:sidetree"

	testDID = "did:method:abc"

	activityPubURL = "http://localhost/services/orb"
	casURL         = "http://localhost/cas"

	testMaxWitnessDelay = 600 * time.Second

	signWithLocalWitness = true
)

func TestNew(t *testing.T) {
	var anchorCh chan []string

	var vcCh chan *verifiable.Credential

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		AnchorGraph:     graph.New(&graph.Providers{}),
		DidAnchors:      memdidanchor.New(),
		AnchorBuilder:   &mockTxnBuilder{},
		VerifiableStore: vcStore,
	}

	c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)
	require.NotNil(t, c)
}

func TestWriter_WriteAnchor(t *testing.T) {
	graphProviders := &graph.Providers{
		Cas:       mocks.NewMockCasClient(nil),
		Pkf:       pubKeyFetcherFnc,
		DocLoader: testutil.GetLoader(t),
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	anchorGraph := graph.New(graphProviders)

	t.Run("success - no local witness configured", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			OpProcessor:     &mockOpProcessor{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			MonitoringSvc:   &mockMonitoring{},
			WitnessStore:    &mockWitnessStore{},
			ActivityStore:   &mockActivityStore{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, false)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin.com",
			},
			{
				UniqueSuffix: "did-2",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin-2.com",
			},
			{
				UniqueSuffix: "did-3",
				Type:         operation.TypeCreate,
				AnchorOrigin: c.apServiceIRI.String(),
			},
		}

		err = c.WriteAnchor("1.anchor", opRefs, 1)
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		vcCh <- anchorVC
	})

	t.Run("success - local witness configured, sign with default witness is false", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			OpProcessor:     &mockOpProcessor{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			MonitoringSvc:   &mockMonitoring{},
			Witness:         &mockWitness{},
			WitnessStore:    &mockWitnessStore{},
			ActivityStore:   &mockActivityStore{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, false)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin.com",
			},
		}

		err = c.WriteAnchor("1.anchor", opRefs, 1)
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		vcCh <- anchorVC
	})

	t.Run("success - local witness", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			OpProcessor:     &mockOpProcessor{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			Witness:         &mockWitness{},
			MonitoringSvc:   &mockMonitoring{},
			WitnessStore:    &mockWitnessStore{},
			ActivityStore:   &mockActivityStore{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: activityPubURL,
			},
			{
				UniqueSuffix: "did-2",
				Type:         operation.TypeCreate,
				AnchorOrigin: activityPubURL,
			},
		}

		err = c.WriteAnchor("1.anchor", opRefs, 1)
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		vcCh <- anchorVC
	})

	t.Run("error - failed to get witness list", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      &mockDidAnchor{},
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			MonitoringSvc:   &mockMonitoring{},
			WitnessStore:    &mockWitnessStore{},
			ActivityStore:   &mockActivityStore{},
			VerifiableStore: vcStore,
			OpProcessor:     &mockOpProcessor{Err: errors.New("operation processor error")},
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
				AnchorOrigin: "origin.com",
			},
		}

		err = c.WriteAnchor("1.anchor", opRefs, 1)
		require.Error(t, err)
		require.Equal(t, err.Error(), "failed to create witness list: operation processor error")
	})

	t.Run("error - build anchor credential error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{Err: errors.New("sign error")},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{},
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err := c.WriteAnchor("1.anchor", []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeCreate}}, 1)
		require.Contains(t, err.Error(), "failed to build anchor credential: sign error")
	})

	t.Run("error - anchor credential signing error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{Err: fmt.Errorf("signer error")},
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err := c.WriteAnchor("1.anchor", getOperationReferences(), 1)

		require.Contains(t, err.Error(), "failed to sign anchor credential[http://domain.com/vc/123]: signer error")
	})

	t.Run("error - local witness (monitoring error)", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			OpProcessor:     &mockOpProcessor{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			Witness:         &mockWitness{},
			MonitoringSvc:   &mockMonitoring{Err: fmt.Errorf("monitoring error")},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.WriteAnchor("1.anchor", getOperationReferences(), 1)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to setup monitoring for local witness for anchor credential[http://domain.com/vc/123]: monitoring error")
	})

	t.Run("error - local witness log error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchor.New(),
			AnchorBuilder: &mockTxnBuilder{},
			Outbox:        &mockOutbox{},
			Signer:        &mockSigner{},
			Witness:       &mockWitness{Err: fmt.Errorf("witness error")},
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err := c.WriteAnchor("1.anchor", getOperationReferences(), 1)
		require.Contains(t, err.Error(),
			"local witnessing failed for anchor credential[http://domain.com/vc/123]: witness error")
	})

	t.Run("error - store anchor credential error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		storeProviderWithErr := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("error put"),
		})

		vcStoreWithErr, err := vcstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStoreWithErr,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.WriteAnchor("1.anchor", getOperationReferences(), 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - store anchor credential error (local witness)", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		storeProviderWithErr := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("error put (local witness)"),
		})

		vcStoreWithErr, err := vcstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			Witness:         &mockWitness{},
			MonitoringSvc:   &mockMonitoring{},
			VerifiableStore: vcStoreWithErr,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.WriteAnchor("1.anchor", getOperationReferences(), 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put (local witness)")
	})

	t.Run("error - previous did anchor reference not found for non-create operations", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeUpdate}}, 1)
		require.Contains(t, err.Error(),
			"previous did anchor reference not found for update operation for did[did:method:abc]")
	})
}

func TestWriter_handle(t *testing.T) {
	graphProviders := &graph.Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	anchorGraph := graph.New(graphProviders)

	t.Run("success", func(t *testing.T) {
		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStore,
		}

		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - save anchor credential to store error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		storeProviderWithErr := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("error put"),
		})

		vcStoreWithErr, err := vcstore.New(storeProviderWithErr, testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStoreWithErr,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - add anchor credential to txn graph error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     &mockAnchorGraph{Err: errors.New("txn graph error")},
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - add anchor credential cid to did anchors error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      &mockDidAnchor{Err: errors.New("did references error")},
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{},
			Signer:          &mockSigner{},
			VerifiableStore: vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - outbox error", func(t *testing.T) {
		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:     anchorGraph,
			DidAnchors:      memdidanchor.New(),
			AnchorBuilder:   &mockTxnBuilder{},
			Outbox:          &mockOutbox{Err: errors.New("outbox error")},
			VerifiableStore: vcStore,
		}

		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c.handle(anchorVC)
	})
}

func TestWriter_postOfferActivity(t *testing.T) {
	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{"https://abc.com/services/orb"})
		require.NoError(t, err)
	})

	t.Run("error - get witnesses URIs error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox: &mockOutbox{},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{":xyz"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})

	t.Run("error - get system URI error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox:        &mockOutbox{},
			ActivityStore: &mockActivityStore{},
			WitnessStore:  &mockWitnessStore{},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, &url.URL{Host: "?!?"}, casIRI, providers, anchorCh, vcCh,
			testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse system witness path")
	})

	t.Run("error - witness proof store error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{Err: fmt.Errorf("witness store error")},
			ActivityStore: &mockActivityStore{},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to store witnesses for vcID[http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d]: witness store error")
	})

	t.Run("error - activity store error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox:        &mockOutbox{},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{Err: fmt.Errorf("activity store error")},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to query references for system witnesses: activity store error")
	})

	t.Run("error - post offer to outbox error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{
			Outbox:        &mockOutbox{Err: fmt.Errorf("outbox error")},
			WitnessStore:  &mockWitnessStore{},
			ActivityStore: &mockActivityStore{},
		}

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		err = c.postOfferActivity(anchorVC, []string{"https://abc.com/services/orb"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to post offer for vcID[http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d]: outbox error")
	})
}

func TestWriter_getWitnesses(t *testing.T) {
	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: "origin-1.com"},
			"did-2": {AnchorOrigin: "origin-2.com"},
			"did-3": {AnchorOrigin: "origin-3.com"},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
			},
			{
				UniqueSuffix: "did-2",
				Type:         operation.TypeRecover,
				AnchorOrigin: "new-origin-2.com",
			},
			{
				UniqueSuffix: "did-3",
				Type:         operation.TypeDeactivate,
			},
			{
				UniqueSuffix: "did-4",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin-4.com",
			},
			{
				UniqueSuffix: "did-5",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin-5.com",
			},
			{
				UniqueSuffix: "did-6",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin-5.com", // test re-use same origin
			},
		}

		witnesses, err := c.getWitnesses(opRefs)
		require.NoError(t, err)
		require.Equal(t, 5, len(witnesses))

		expected := []string{"origin-1.com", "new-origin-2.com", "origin-3.com", "origin-4.com", "origin-5.com"}
		require.Equal(t, expected, witnesses)
	})

	t.Run("error - operation type not supported", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: "origin-1.com"},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         "invalid",
			},
		}

		witnesses, err := c.getWitnesses(opRefs)
		require.Error(t, err)
		require.Nil(t, witnesses)
		require.Equal(t, err.Error(), "operation type 'invalid' not supported for assembling witness list")
	})

	t.Run("error - unexpected interface for anchor origin", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		opMap := map[string]*protocol.ResolutionModel{
			"did-1": {AnchorOrigin: 0},
		}

		providers := &Providers{
			OpProcessor: &mockOpProcessor{Map: opMap},
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeUpdate,
			},
		}

		witnesses, err := c.getWitnesses(opRefs)
		require.Error(t, err)
		require.Nil(t, witnesses)
		require.Contains(t, err.Error(), "unexpected interface 'int' for anchor origin")
	})
}

func TestWriter_getBatchWitnessesIRI(t *testing.T) {
	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	anchorCh := make(chan []string, 100)
	vcCh := make(chan *verifiable.Credential, 100)

	c := New(namespace, apServiceIRI, nil, &Providers{}, anchorCh, vcCh, testMaxWitnessDelay, true)

	t.Run("success", func(t *testing.T) {
		witnesses := []string{"origin-1.com", "origin-2.com"}

		witnessesIRI, err := c.getBatchWitnessesIRI(witnesses)
		require.NoError(t, err)

		// two from witness list
		require.Equal(t, 2, len(witnessesIRI))
	})

	t.Run("success - exclude current domain from witness list", func(t *testing.T) {
		witnesses := []string{activityPubURL}

		witnessesIRI, err := c.getBatchWitnessesIRI(witnesses)
		require.NoError(t, err)

		require.Equal(t, 0, len(witnessesIRI))
	})

	t.Run("error - invalid url", func(t *testing.T) {
		witnesses := []string{":xyz"}

		witnessesIRI, err := c.getBatchWitnessesIRI(witnesses)
		require.Error(t, err)
		require.Nil(t, witnessesIRI)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})
}

func TestWriter_Read(t *testing.T) {
	graphProviders := &graph.Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
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
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh, testMaxWitnessDelay, signWithLocalWitness)

		more, entries := c.Read(-1)
		require.False(t, more)
		require.Empty(t, entries)
	})
}

type mockTxnBuilder struct {
	Err error
}

func (m *mockTxnBuilder) Build(payload *subject.Payload) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return &verifiable.Credential{Subject: payload, ID: "http://domain.com/vc/123"}, nil
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}

type mockAnchorGraph struct {
	Err error
}

func (m *mockAnchorGraph) Add(vc *verifiable.Credential) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}

	return "cid", nil
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

type mockOpProcessor struct {
	Err error
	Map map[string]*protocol.ResolutionModel
}

func (m *mockOpProcessor) Resolve(uniqueSuffix string) (*protocol.ResolutionModel, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.Map[uniqueSuffix], nil
}

type mockOutbox struct {
	Err error
}

func (m *mockOutbox) Post(activity *vocab.ActivityType) (*url.URL, error) {
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
	Err error
}

func (w *mockWitness) Witness(anchorCred []byte) ([]byte, error) {
	if w.Err != nil {
		return nil, w.Err
	}

	return anchorCred, nil
}

type mockMonitoring struct {
	Err error
}

func (m *mockMonitoring) Watch(_ string, _ time.Time, _ []byte) error {
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

	systemWitnessIRI, err := url.Parse("origin-2.com")
	if err != nil {
		return nil, err
	}

	iter := &apmocks.ReferenceIterator{}

	iter.NextReturnsOnCall(0, systemWitnessIRI, nil)
	iter.NextReturnsOnCall(1, nil, spi.ErrNotFound)

	return iter, nil
}

type mockWitnessStore struct {
	Err error
}

func (w *mockWitnessStore) Put(vcID string, witnesses []*proof.WitnessProof) error {
	if w.Err != nil {
		return w.Err
	}

	return nil
}

func getOperationReferences() []*operation.Reference {
	return []*operation.Reference{
		{
			UniqueSuffix: "did-1",
			Type:         operation.TypeCreate,
			AnchorOrigin: activityPubURL,
		},
	}
}

//nolint: lll
var anchorCred = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "credentialSubject": {
    "coreIndex": "QmZzPwGc3JEMQDiJu21YZcdpEPam7qCoXPLEUQXn34sMhB",
    "namespace": "did:sidetree",
    "operationCount": 1,
    "previousAnchors": {
      "EiBjG9z921eyj8wI4j-LAqsJBRC_GalIUWPJeXGekxFQ-w": ""
    },
    "version": 0
  },
  "id": "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
  "issuanceDate": "2021-03-17T20:01:10.4002903Z",
  "issuer": "http://peer1.com",
  "proof": {
    "created": "2021-03-17T20:01:10.4024292Z",
    "domain": "domain.com",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..pHA1rMSsHBJLbDwRpNY0FrgSgoLzBw4S7VP7d5bkYW-JwU8qc_4CmPfQctR8kycQHSa2Jh8LNBqNKMeVWsAwDA",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc#CvSyX0VxMCbg-UiYpAVd9OmhaFBXBr5ISpv2RZ2c9DY"
  },
  "type": "VerifiableCredential"
}`
