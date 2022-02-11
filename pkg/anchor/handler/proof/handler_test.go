/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
	proofapi "github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	anchoreventstore "github.com/trustbloc/orb/pkg/store/anchorevent"
	"github.com/trustbloc/orb/pkg/store/anchoreventstatus"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/store/witness"
)

//go:generate counterfeiter -o ../mocks/monitoring.gen.go --fake-name MonitoringService . monitoringSvc
//go:generate counterfeiter -o ../mocks/anchorindexstatus.gen.go --fake-name AnchorIndexStatusStore . statusStore

const (
	anchorID                 = "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d"
	witnessURL               = "http://example.com/orb/services"
	configStoreName          = "orb-config"
	defaultPolicyCacheExpiry = 5 * time.Second
)

func TestNew(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})

	store, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		AnchorEventStore: store,
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
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEvent), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), witnesses)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    &mockWitnessPolicy{eval: false},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(), expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - proof expired", func(t *testing.T) {
		proofHandler := New(&Providers{}, ps)

		expiredTime := time.Now().Add(-60 * time.Second)

		err := proofHandler.HandleProof(witnessIRI, anchorID, expiredTime, nil)
		require.NoError(t, err)
	})

	t.Run("success - witness policy satisfied", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		emptyWitnessProofs := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - status is completed", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{eval: true},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - policy satisfied but some witness proofs are empty", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore: &mockWitnessStore{WitnessProof: []*proofapi.WitnessProof{{
				Type: proofapi.WitnessTypeSystem,
				URI:  witnessIRI,
			}}},
			WitnessPolicy: &mockWitnessPolicy{eval: true},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("success - duplicate proofs", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		emptyWitnessProofs := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), emptyWitnessProofs)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(duplicateWitnessProof))
		require.NoError(t, err)
	})

	t.Run("error - get status error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), witnesses)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturns("", fmt.Errorf("get status error"))

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      mockStatusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor event [%s]: get status error", ae.Index().String()))
	})

	t.Run("error - second get status error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), witnesses)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturnsOnCall(0, proofapi.AnchorIndexStatusInProcess, nil)
		mockStatusStore.GetStatusReturnsOnCall(1, "", fmt.Errorf("second get status error"))

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      mockStatusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor event [%s]: second get status error", ae.Index().String()))
	})

	t.Run("error - set status to complete error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), witnesses)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.AddStatusReturns(fmt.Errorf("add status error"))

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      mockStatusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to change status to 'completed' for anchor event [%s]: add status error", ae.Index().String()))
	})

	t.Run("status already completed", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: witnessIRI}}
		err = witnessStore.Put(ae.Index().String(), witnesses)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturnsOnCall(0, proofapi.AnchorIndexStatusInProcess, nil)
		mockStatusStore.GetStatusReturnsOnCall(1, proofapi.AnchorIndexStatusCompleted, nil)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      mockStatusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     witnessStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("error - witness policy error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{Err: fmt.Errorf("witness policy error")},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(),
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to evaluate witness policy for anchor event [%s]: witness policy error", ae.Index().String()))
	})

	t.Run("error - status not found store error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore, // error will be returned b/c we didn't set "in-process" status for anchor
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, "testVC",
			expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "status not found for anchor event[testVC]")
	})

	t.Run("error - store error", func(t *testing.T) {
		store := &storemocks.Store{}
		store.GetReturns(nil, fmt.Errorf("get error"))

		provider := &storemocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		aeStore, err := anchoreventstore.New(provider, testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(anchorID, proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorID, expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get anchor event: get error")
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{AddProofErr: fmt.Errorf("witness store error")},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(), expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEventTwoProofs), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{GetErr: fmt.Errorf("witness store error")},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(), expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - unmarshal witness proof", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(anchorID, proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    &mocks.MonitoringService{},
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, anchorID, expiryTime, []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal incoming witness proof for anchor event")
	})

	t.Run("error - monitoring error", func(t *testing.T) {
		aeStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		ae := &vocab.AnchorEventType{}
		require.NoError(t, json.Unmarshal([]byte(anchorEvent), ae))

		err = aeStore.Put(ae)
		require.NoError(t, err)

		monitoringSvc := &mocks.MonitoringService{}
		monitoringSvc.WatchReturns(fmt.Errorf("monitoring error"))

		statusStore, err := anchoreventstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(ae.Index().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: aeStore,
			StatusStore:      statusStore,
			MonitoringSvc:    monitoringSvc,
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{},
			Metrics:          &orbmocks.MetricsProvider{},
			DocLoader:        testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps)

		err = proofHandler.HandleProof(witnessIRI, ae.Index().String(), expiryTime, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "monitoring error")
	})
}

type mockWitnessStore struct {
	WitnessProof []*proofapi.WitnessProof
	AddProofErr  error
	GetErr       error
}

func (w *mockWitnessStore) AddProof(_ string, _ *url.URL, _ []byte) error {
	if w.AddProofErr != nil {
		return w.AddProofErr
	}

	return nil
}

func (w *mockWitnessStore) Get(_ string) ([]*proofapi.WitnessProof, error) {
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
const anchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:EiCIZ19PGWe_65JLcIp_bmOu_ZrPOerFPXAoXAcdWW7iCg\",\"previousAnchor\":\"hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw\"}]},\"subject\":\"hl:uEiC0arCOQrIDw2F2Zca10gEutIrHWgIUaC1jPDRRBLADUQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQzBhckNPUXJJRHcyRjJaY2ExMGdFdXRJckhXZ0lVYUMxalBEUlJCTEFEVVE\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA\",\"id\":\"https://orb.domain2.com/vc/1636951e-9117-4134-904a-e0cd177517a1\",\"issuanceDate\":\"2022-02-10T18:50:48.682168399Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T18:50:48.682348236Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fqgLBKohg962_3GNbH-QXklA89KBMHev95-Pk1XcGa47jq0TbFUeZi3DBGLgc-pDBisqkh0U3bUSvKY_edBAAw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T18:50:48.729Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..xlI19T5KT-Sy1CJuCQLIhgGHdlaK0dIjoctRwzJUz6-TpiluluGEa69aCuDjx426TgHvGXJDn8jHi5aDqGuTDA\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA",
  "parent": "hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWswQ1V1SUlWT3hsYWxZSDZKVTdnc0l3dm81ekdOY01fellvMmpYd3pCenc",
  "published": "2022-02-10T18:50:48.681998572Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const anchorEventTwoProofs = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uAAA:EiCjNbfvKWZDsa59BcLw0TE9t6JrY6D8N9T_8GKnuI8oxw\"},{\"id\":\"did:orb:uAAA:EiBlxzs4KPQ0H4zJHFVwY7x3UGuJe4Lro9HMr2SXz0LUDw\"},{\"id\":\"did:orb:uAAA:EiDhm7PZtsT6V9kwr5Uxcr_CJgobAVqQlGNG4_3r4TQQFA\"},{\"id\":\"did:orb:uAAA:EiAFi_-TaUuSa4C991o0BhFoJwxkEtRiQDSb3x_H76XyGQ\"},{\"id\":\"did:orb:uAAA:EiDoYvqwqqo9YSkqBB0LEM0oxkn1ouRfnMlHN1mlCoJKxw\"},{\"id\":\"did:orb:uAAA:EiCDzGTIVFUr3YCyWiyzExvOAMwogn29XOM01Y6v9kKKiA\"}]},\"subject\":\"hl:uEiBuyLBSjEYws4_MZyoD9Bt7rXsnVNKkM1eX0rB5SDQeGA:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQnV5TEJTakVZd3M0X01aeW9EOUJ0N3JYc25WTktrTTFlWDByQjVTRFFlR0E\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiDM_cyudC07RwQF0hrtk_J7_l0jg9S01slXwz6f9aI_2A",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiB4mpKUX0qR40jurnRBlNb2iXRb5-AqgBskZOMC1nA2QA"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiB4mpKUX0qR40jurnRBlNb2iXRb5-AqgBskZOMC1nA2QA\",\"id\":\"https://orb.domain2.com/vc/1588d22b-2461-4347-a150-afee8e7cf5c7\",\"issuanceDate\":\"2022-02-10T19:27:32.200199824Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T19:27:32.200372694Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..CjOYK7XH7zyH3-Gtg54rFkuOaIt9W4Ov8uYksHPJeBNmTHBdwmyyJ6yExguDQ2yak6KvgeIou70_za4QHWIBCw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T19:27:32.306Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..bRPBmMYeBTjO01M4QHXmsfZNSL8gmPTdhac7yQkTpWiDgpykXs_KyVdBtuA5rvUBsfsfCzDSgvp15SmufDXaDQ\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiDM_cyudC07RwQF0hrtk_J7_l0jg9S01slXwz6f9aI_2A"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiB4mpKUX0qR40jurnRBlNb2iXRb5-AqgBskZOMC1nA2QA",
  "published": "2022-02-10T19:27:32.198982074Z",
  "type": "AnchorEvent"
}`

//nolint:lll
const witnessProof = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
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

//nolint:lll
const duplicateWitnessProof = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "proof": {
    "created": "2021-10-14T18:32:17.91Z",
    "domain": "http://orb.vct:8077/maple2020",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..h3-0HC3L87TM0j0o3Nd0VLlalcVVphwOPsfdkCLZ4q-uL4z8eO2vQ4sobbtOtFpNNZlpIOQnaWJMX3Ch5Wh-AQ",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:orb.domain1.com#orb1key"
  }
}`
