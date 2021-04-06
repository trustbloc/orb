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

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/didanchorref/memdidanchorref"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
)

const (
	namespace = "did:sidetree"

	testDID = "did:method:abc"

	activityPubURL = "http://localhost/activityPubURL"
	casURL         = "http://localhost/cas"
)

func TestNew(t *testing.T) {
	var anchorCh chan []string

	var vcCh chan *verifiable.Credential

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
	require.NoError(t, err)

	providers := &Providers{
		AnchorGraph:   graph.New(&graph.Providers{}),
		DidAnchors:    memdidanchorref.New(),
		AnchorBuilder: &mockTxnBuilder{},
		ProofHandler:  &mockProofHandler{vcCh: make(chan *verifiable.Credential, 100)},
		Outbox:        &mockOutbox{},
		Store:         vcStore,
	}

	c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)
	require.NotNil(t, c)
}

func TestWriter_WriteAnchor(t *testing.T) {
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
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: make(chan *verifiable.Credential, 100)},
			OpProcessor:   &mockOpProcessor{},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

		opRefs := []*operation.Reference{
			{
				UniqueSuffix: "did-1",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin.com",
			},
			{
				UniqueSuffix: "did-2",
				Type:         operation.TypeCreate,
				AnchorOrigin: "origin.com",
			},
		}

		err = c.WriteAnchor("1.anchor", opRefs, 1)
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		vcCh <- anchorVC
	})

	t.Run("error - failed to get witness list", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    &mockDidTxns{},
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
			OpProcessor:   &mockOpProcessor{Err: errors.New("operation processor error")},
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{Err: errors.New("sign error")},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh)

		err := c.WriteAnchor("1.anchor", []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeCreate}}, 1)
		require.Contains(t, err.Error(), "failed to build anchor credential: sign error")
	})

	t.Run("error - store anchor credential error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		storeProviderWithErr := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("error put"),
		})

		vcStoreWithErr, err := vcstore.New(storeProviderWithErr)
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStoreWithErr,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh)

		err = c.WriteAnchor("1.anchor", []*operation.Reference{{UniqueSuffix: testDID, Type: operation.TypeCreate}}, 1)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - previous did anchor reference not found for non-create operations", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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
		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: make(chan *verifiable.Credential, 100)},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
		}

		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
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

		vcStoreWithErr, err := vcstore.New(storeProviderWithErr)
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStoreWithErr,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - add anchor credential to txn graph error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:   &mockAnchorGraph{Err: errors.New("txn graph error")},
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - add anchor credential cid to did anchors error", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providersWithErr := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    &mockDidTxns{Err: errors.New("did references error")},
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: vcCh},
			Outbox:        &mockOutbox{},
			Store:         vcStore,
		}

		c := New(namespace, apServiceIRI, casIRI, providersWithErr, anchorCh, vcCh)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		c.handle(anchorVC)
	})

	t.Run("error - outbox error", func(t *testing.T) {
		vcStore, err := vcstore.New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		providers := &Providers{
			AnchorGraph:   anchorGraph,
			DidAnchors:    memdidanchorref.New(),
			AnchorBuilder: &mockTxnBuilder{},
			ProofHandler:  &mockProofHandler{vcCh: make(chan *verifiable.Credential, 100)},
			Outbox:        &mockOutbox{Err: errors.New("outbox error")},
			Store:         vcStore,
		}

		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		c.handle(anchorVC)
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

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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

func TestWriter_Read(t *testing.T) {
	graphProviders := &graph.Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
	}

	providers := &Providers{
		AnchorGraph: graph.New(graphProviders),
		DidAnchors:  memdidanchorref.New(),
	}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	casIRI, err := url.Parse(casURL)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		anchorCh := make(chan []string, 100)
		vcCh := make(chan *verifiable.Credential, 100)

		c := New(namespace, apServiceIRI, casIRI, providers, anchorCh, vcCh)

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

type mockProofHandler struct {
	vcCh chan *verifiable.Credential
}

func (m *mockProofHandler) RequestProofs(vc *verifiable.Credential, _ []string) error {
	m.vcCh <- vc

	return nil
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

type mockDidTxns struct {
	Err error
}

func (m *mockDidTxns) Add(_ []string, _ string) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

func (m *mockDidTxns) Last(did string) (string, error) {
	return "cid", nil
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

func (m *mockOutbox) Post(activity *vocab.ActivityType) error {
	if m.Err != nil {
		return m.Err
	}

	return nil
}

//nolint:gochecknoglobals,lll
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
