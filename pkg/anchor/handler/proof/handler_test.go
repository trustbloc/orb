/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	"github.com/trustbloc/orb/pkg/anchor/policy"
	proofapi "github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/store/vcstatus"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
	"github.com/trustbloc/orb/pkg/store/witness"
)

//go:generate counterfeiter -o ../mocks/monitoring.gen.go --fake-name MonitoringService . monitoringSvc
//go:generate counterfeiter -o ../mocks/vcstatus.gen.go --fake-name VCStatusStore . vcStatusStore

const (
	vcID                     = "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d"
	witnessURL               = "http://example.com/orb/services"
	configStoreName          = "orb-config"
	defaultPolicyCacheExpiry = 5 * time.Second
)

func TestNew(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})

	store, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		VCStore: store,
	}

	c := New(providers, ps)
	require.NotNil(t, c)
}

func TestWitnessProofHandler(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	witnessIRI, outerErr := url.Parse(witnessURL)
	require.NoError(t, outerErr)

	configStore, outerErr := mem.NewProvider().OpenStore(configStoreName)
	require.NoError(t, outerErr)

	expiryTime := time.Now().Add(60 * time.Second)

	t.Run("success - witness policy not satisfied", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(anchorVC.ID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider())
		require.NoError(t, err)

		// prepare witness store with 'empty' witness proofs
		emptyWitnessProofs := []*proofapi.WitnessProof{{Type: proofapi.WitnessTypeSystem, Witness: witnessIRI.String()}}
		err = witnessStore.Put(vcID, emptyWitnessProofs)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  witnessStore,
			WitnessPolicy: &mockWitnessPolicy{eval: false},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - proof expired", func(t *testing.T) {
		proofHandler := New(&Providers{}, ps)

		expiredTime := time.Now().Add(-60 * time.Second)

		err := proofHandler.HandleProof(witnessIRI, vcID, expiredTime, nil)
		require.NoError(t, err)
	})

	t.Run("success - witness policy satisfied", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(anchorVC.ID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider())
		require.NoError(t, err)

		// prepare witness store with 'empty' witness proofs
		emptyWitnessProofs := []*proofapi.WitnessProof{{Type: proofapi.WitnessTypeSystem, Witness: witnessIRI.String()}}
		err = witnessStore.Put(anchorVC.ID, emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - vc status is completed", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(anchorVC.ID, proofapi.VCStatusCompleted)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{eval: true},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - policy satisfied but some witness proofs are empty", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(anchorVC.ID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore: &mockWitnessStore{WitnessProof: []*proofapi.WitnessProof{{
				Type:    proofapi.WitnessTypeSystem,
				Witness: "witness",
			}}},
			WitnessPolicy: &mockWitnessPolicy{eval: true},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("error - get vc status error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider())
		require.NoError(t, err)

		// prepare witness store with 'empty' witness proofs
		emptyWitnessProofs := []*proofapi.WitnessProof{{Type: proofapi.WitnessTypeSystem, Witness: witnessIRI.String()}}
		err = witnessStore.Put(anchorVC.ID, emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockVCStatusStore := &mocks.VCStatusStore{}
		mockVCStatusStore.GetStatusReturns("", fmt.Errorf("get vc status error"))

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: mockVCStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor credential[%s]: get vc status error", anchorVC.ID))
	})

	t.Run("error - second get vc status error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider())
		require.NoError(t, err)

		// prepare witness store with 'empty' witness proofs
		emptyWitnessProofs := []*proofapi.WitnessProof{{Type: proofapi.WitnessTypeSystem, Witness: witnessIRI.String()}}
		err = witnessStore.Put(anchorVC.ID, emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockVCStatusStore := &mocks.VCStatusStore{}
		mockVCStatusStore.GetStatusReturnsOnCall(0, proofapi.VCStatusInProcess, nil)
		mockVCStatusStore.GetStatusReturnsOnCall(1, "", fmt.Errorf("second get vc status error"))

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: mockVCStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor credential[%s]: second get vc status error", anchorVC.ID))
	})

	t.Run("error - set vc status to complete error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider())
		require.NoError(t, err)

		// prepare witness store with 'empty' witness proofs
		emptyWitnessProofs := []*proofapi.WitnessProof{{Type: proofapi.WitnessTypeSystem, Witness: witnessIRI.String()}}
		err = witnessStore.Put(anchorVC.ID, emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockVCStatusStore := &mocks.VCStatusStore{}
		mockVCStatusStore.AddStatusReturns(fmt.Errorf("add vc status error"))

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: mockVCStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to change status to 'completed' for credential[%s]: add vc status error", anchorVC.ID))
	})

	t.Run("error - witness policy error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(anchorVC.ID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{Err: fmt.Errorf("witness policy error")},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorVC.ID,
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to evaluate witness policy for credential[%s]: witness policy error", anchorVC.ID))
	})

	t.Run("error - vc status not found store error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential(
			[]byte(anchorCredTwoProofs),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore, // error will be returned b/c we didn't set "in-process" status for vc
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, "testVC",
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "status not found for vcID: testVC")
	})

	t.Run("error - store error", func(t *testing.T) {
		store := &storemocks.Store{}
		store.GetReturns(nil, fmt.Errorf("get error"))

		provider := &storemocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		vcStore, err := vcstore.New(provider, testutil.GetLoader(t))
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(vcID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get vc: get error")
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(vcID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{AddProofErr: fmt.Errorf("witness store error")},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to add witness[http://example.com/orb/services] proof for credential[http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d]: witness store error") //nolint:lll
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(vcID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{GetErr: fmt.Errorf("witness store error")},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to get witness proofs for credential[http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d]: witness store error") //nolint:lll
	})

	t.Run("error - unmarshal witness proof", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(vcID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: &mocks.MonitoringService{},
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal incoming witness proof for anchor credential")
	})

	t.Run("error - monitoring error", func(t *testing.T) {
		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = vcStore.Put(anchorVC)
		require.NoError(t, err)

		monitoringSvc := &mocks.MonitoringService{}
		monitoringSvc.WatchReturns(fmt.Errorf("monitoring error"))

		vcStatusStore, err := vcstatus.New(mem.NewProvider())
		require.NoError(t, err)

		err = vcStatusStore.AddStatus(vcID, proofapi.VCStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: monitoringSvc,
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, vcID, expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "monitoring error")
	})
}

type mockWitnessStore struct {
	WitnessProof []*proofapi.WitnessProof
	AddProofErr  error
	GetErr       error
}

func (w *mockWitnessStore) AddProof(vcID, witnessID string, proof []byte) error {
	if w.AddProofErr != nil {
		return w.AddProofErr
	}

	return nil
}

func (w *mockWitnessStore) Get(vcID string) ([]*proofapi.WitnessProof, error) {
	if w.GetErr != nil {
		return nil, w.GetErr
	}

	return w.WitnessProof, nil
}

type mockWitnessPolicy struct {
	eval bool
	Err  error
}

func (wp *mockWitnessPolicy) Evaluate(_ []*proofapi.WitnessProof) (bool, error) {
	if wp.Err != nil {
		return false, wp.Err
	}

	return wp.eval, nil
}

//nolint:lll
const anchorCred = `
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

//nolint:lll
const anchorCredTwoProofs = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "credentialSubject": {
    "coreIndex": "QmTTXin1m7Afk3mQJPMZQdCQAafid7eUNsUDYVcLdSRU2s",
    "namespace": "did:orb",
    "operationCount": 1,
    "previousAnchors": {
      "EiAhqN-B6kLoWMqKkqwxeLB5ppo0gOYWhZYA-BmptZ0Tqw": ""
    },
    "version": 0
  },
  "id": "http://orb.domain1.com/vc/9ac66b40-bcc6-4ca8-a9c7-d1fd3eaebafd",
  "issuanceDate": "2021-04-20T20:07:19.873389246Z",
  "issuer": "http://orb.domain1.com",
  "proof": [
    {
      "created": "2021-04-20T20:07:19.875087637Z",
      "domain": "domain1.com",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kIg1Z2DpPwY-0njcMRtc8uEmZqewVSmsTqwFSy97ppU7eubGfwGmu_L5nErfn4OCRkPdlDxZRkXhqW1VY329AA",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:abc.com#2130bhDAK-2jKsOXJiEDG909Jux4rcYEpFsYzVlqdAY"
    },
    {
      "created": "2021-04-20T20:07:20.956Z",
      "domain": "http://orb.vct:8077",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..khSPSqvqDHhOFWzGe7UoyHhr6-RSEPNZwXjOFk31WOWByRwGZMDuaWpDbbe6QYo89lR0dqVQCxs2N7xprqwgAA",
      "proofPurpose": "assertionMethod",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:abc.com#3e2Fq05s-jEYa5BOW0uQKuNOU8nOTzR3-IIQqE5KmPo"
    }
  ],
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ]
}`

//nolint:lll
const witnessProof = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "proof": {
    "created": "2021-04-20T20:05:35.055Z",
    "domain": "http://orb.vct:8077",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PahivkKT6iKdnZDpkLu6uwDWYSdP7frt4l66AXI8mTsBnjgwrf9Pr-y_BkEFqsOMEuwJ3DSFdmAp1eOdTxMfDQ",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc.com#2130bhDAK-2jKsOXJiEDG909Jux4rcYEpFsYzVlqdAY"
  }
}`
