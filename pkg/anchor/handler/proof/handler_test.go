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
	policymocks "github.com/trustbloc/orb/pkg/anchor/witness/policy/mocks"
	proofapi "github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	anchorlinkstore "github.com/trustbloc/orb/pkg/store/anchorlink"
	"github.com/trustbloc/orb/pkg/store/anchorstatus"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/store/witness"
)

//go:generate counterfeiter -o ../mocks/anchorindexstatus.gen.go --fake-name AnchorIndexStatusStore . statusStore
//go:generate counterfeiter -o ../mocks/witnessstore.gen.go --fake-name WitnessStore . witnessStore

const (
	anchorID                 = "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d"
	witnessURL               = "http://orb.vct:8077/maple2020"
	witness2URL              = "https://orb.domain2.com"
	defaultPolicyCacheExpiry = 5 * time.Second
	defaultClockSkew         = 10 * 12 * 30 * 24 * time.Hour // ten years
)

func TestNew(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})

	store, err := anchorlinkstore.New(mem.NewProvider())
	require.NoError(t, err)

	providers := &Providers{
		AnchorLinkStore: store,
	}

	c := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)
	require.NotNil(t, c)
}

//nolint:maintidx
func TestWitnessProofHandler(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	witness1IRI, outerErr := url.Parse(witnessURL)
	require.NoError(t, outerErr)

	witness2IRI, outerErr := url.Parse(witness2URL)
	require.NoError(t, outerErr)

	configStore := &policymocks.PolicyStore{}

	expiryTime := time.Now().Add(60 * time.Second)

	t.Run("success - witness policy not satisfied", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinkset), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}, nil)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,
			WitnessStore:    witnessStore,
			WitnessPolicy:   &mockWitnessPolicy{eval: false},
			Metrics:         &orbmocks.MetricsProvider{},
			DocLoader:       testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(), expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("success - proof expired", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,
			WitnessStore:    witnessStore,
			WitnessPolicy:   witnessPolicy,
			Metrics:         &orbmocks.MetricsProvider{},
			DocLoader:       testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, time.Second)

		expiredTime := time.Now().Add(-60 * time.Second)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiredTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("success - witness policy satisfied", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type:   proofapi.WitnessTypeSystem,
						URI:    vocab.NewURLProperty(witness1IRI),
						HasLog: true,
					},
					Proof: []byte(witnessProofJSONWebSignature),
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,
			WitnessStore:    witnessStore,
			WitnessPolicy:   witnessPolicy,
			Metrics:         &orbmocks.MetricsProvider{},
			DocLoader:       testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("success - status is completed", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,
			WitnessStore:    &mockWitnessStore{},
			WitnessPolicy:   &mockWitnessPolicy{eval: true},
			Metrics:         &orbmocks.MetricsProvider{},
			DocLoader:       testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("success - policy satisfied but some witness proofs are empty", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinkset), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,
			WitnessStore: &mockWitnessStore{WitnessProof: []*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type:   proofapi.WitnessTypeBatch,
						URI:    vocab.NewURLProperty(witness2IRI),
						HasLog: true,
					},
					Proof: []byte(witnessProofED25519Signature2020),
				},
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}},
			WitnessPolicy: &mockWitnessPolicy{eval: true},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("error - vc created ", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{eval: true},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("success - duplicate proofs", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type:   proofapi.WitnessTypeBatch,
						URI:    vocab.NewURLProperty(witness2IRI),
						HasLog: true,
					},
					Proof: []byte(witnessProofED25519Signature2018),
				},
				{
					Witness: &proofapi.Witness{
						Type:   proofapi.WitnessTypeBatch,
						URI:    vocab.NewURLProperty(witness2IRI),
						HasLog: true,
					},
					Proof: []byte(witnessProofED25519Signature2018),
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofED25519Signature2020))
		require.NoError(t, err)
	})

	t.Run("error - invalid anchor link set (no replies hence invalid VC)", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetWithoutReplies), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed get verifiable credential from anchor: no replies in anchor link")
	})

	t.Run("error - vc created date missing", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, time.Second)

		expiredTime := time.Now()

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiredTime, []byte(witnessProofWithoutCreated))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get create time")
	})

	t.Run("error - get status error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		witnessStore, err := witness.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		// prepare witness store
		witnesses := []*proofapi.Witness{{Type: proofapi.WitnessTypeSystem, URI: vocab.NewURLProperty(witness1IRI)}}
		err = witnessStore.Put(al.Anchor().String(), witnesses)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturns("", fmt.Errorf("get status error"))

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     mockStatusStore,

			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor [%s]: get status error", al.Anchor().String()))
	})

	t.Run("error - second get status error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturnsOnCall(0, proofapi.AnchorIndexStatusInProcess, nil)
		mockStatusStore.GetStatusReturnsOnCall(1, "", fmt.Errorf("second get status error"))

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     mockStatusStore,

			WitnessStore:  &mocks.WitnessStore{},
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to get status for anchor [%s]: second get status error", al.Anchor().String()))
	})

	t.Run("error - set status to complete error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.AddStatusReturns(fmt.Errorf("add status error"))

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     mockStatusStore,

			WitnessStore:  &mocks.WitnessStore{},
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to change status to 'completed' for anchor [%s]: add status error", al.Anchor().String()))
	})

	t.Run("status already completed", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		witnessStore := &mocks.WitnessStore{}
		witnessStore.GetReturns(
			[]*proofapi.WitnessProof{
				{
					Witness: &proofapi.Witness{
						Type: proofapi.WitnessTypeSystem,
						URI:  vocab.NewURLProperty(witness1IRI),
					},
				},
			}, nil)

		witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)

		mockStatusStore := &mocks.AnchorIndexStatusStore{}
		mockStatusStore.GetStatusReturnsOnCall(0, proofapi.AnchorIndexStatusInProcess, nil)
		mockStatusStore.GetStatusReturnsOnCall(1, proofapi.AnchorIndexStatusCompleted, nil)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     mockStatusStore,

			WitnessStore:  witnessStore,
			WitnessPolicy: witnessPolicy,
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.NoError(t, err)
	})

	t.Run("error - witness policy error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{Err: fmt.Errorf("witness policy error")},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf(
			"failed to evaluate witness policy for anchor [%s]: witness policy error", al.Anchor().String()))
	})

	t.Run("error - status not found store error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore, // error will be returned b/c we didn't set "in-process" status for anchor

			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(),
			expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), "status not found for anchor [hl:uEiABbKSeh3rb4MOjS1Era2_62bBPwP9EytPSg5tIkNYiSQ]")
	})

	t.Run("error - store error", func(t *testing.T) {
		store := &storemocks.Store{}
		store.GetReturns(nil, fmt.Errorf("get error"))

		provider := &storemocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		aeStore, err := anchorlinkstore.New(provider)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(anchorID, proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
			Metrics:       &orbmocks.MetricsProvider{},
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, anchorID, expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get anchor link: get error")
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{AddProofErr: fmt.Errorf("witness store error")},
			WitnessPolicy: &mockWitnessPolicy{},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(), expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - witness store add proof error", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		als := &linkset.Linkset{}
		require.NoError(t, json.Unmarshal([]byte(anchorLinksetTwoProofs), als))

		al := als.Link()
		require.NotNil(t, al)

		err = aeStore.Put(al)
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(al.Anchor().String(), proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{GetErr: fmt.Errorf("witness store error")},
			WitnessPolicy: &mockWitnessPolicy{},
			Metrics:       &orbmocks.MetricsProvider{},
			DocLoader:     testutil.GetLoader(t),
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, al.Anchor().String(), expiryTime, []byte(witnessProofJSONWebSignature))
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - unmarshal witness proof", func(t *testing.T) {
		aeStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		statusStore, err := anchorstatus.New(mem.NewProvider(), testutil.GetExpiryService(t), time.Minute)
		require.NoError(t, err)

		err = statusStore.AddStatus(anchorID, proofapi.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: aeStore,
			StatusStore:     statusStore,

			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
			Metrics:       &orbmocks.MetricsProvider{},
		}

		proofHandler := New(providers, ps, datauri.MediaTypeDataURIGzipBase64, defaultClockSkew)

		err = proofHandler.HandleProof(witness1IRI, anchorID, expiryTime, []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal incoming witness proof for anchor")
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

const anchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiABbKSeh3rb4MOjS1Era2_62bBPwP9EytPSg5tIkNYiSQ",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
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
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ1dLTTZxMWZHcWxwVzRIanBYWVA1S2JNOGJMUlF2X3daa0R3eVZfcnBfSlE%22%7D%2C%7B%22href%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ18xN0I3d0dHUTYxU1ppMlFEUU1wUWNCLWNxTFp6MW1kQk9QY1QzY0FaQkE%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fd53b1df9-1acf-4389-a006-0f88496afe46%22%2C%22issuanceDate%22%3A%222022-03-15T21%3A21%3A54.62437567Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-03-15T21%3A21%3A54.631Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22gRPF8XAA4iYMwl26RmFGUoN99wuUnD_igmvIlzzDpPRLVDtmA8wrNbUdJIAKKhyMJFju8OjciSGYMY_bDRjBAw%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`

const anchorLinksetTwoProofs = `{
  "linkset": [
    {
      "anchor": "hl:uEiABbKSeh3rb4MOjS1Era2_62bBPwP9EytPSg5tIkNYiSQ",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
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
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ1dLTTZxMWZHcWxwVzRIanBYWVA1S2JNOGJMUlF2X3daa0R3eVZfcnBfSlE%22%7D%2C%7B%22href%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ18xN0I3d0dHUTYxU1ppMlFEUU1wUWNCLWNxTFp6MW1kQk9QY1QzY0FaQkE%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
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

const anchorLinksetWithoutReplies = `{
  "linkset": [
    {
      "anchor": "hl:uEiABbKSeh3rb4MOjS1Era2_62bBPwP9EytPSg5tIkNYiSQ",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
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
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ1dLTTZxMWZHcWxwVzRIanBYWVA1S2JNOGJMUlF2X3daa0R3eVZfcnBfSlE%22%7D%2C%7B%22href%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ18xN0I3d0dHUTYxU1ppMlFEUU1wUWNCLWNxTFp6MW1kQk9QY1QzY0FaQkE%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
      ]
    }
  ]
}`

const witnessProofJSONWebSignature = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "proof": {
    "created": "2021-04-20T20:05:35.055Z",
    "domain": "http://orb.vct:8077/maple2020",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PahivkKT6iKdnZDpkLu6uwDWYSdP7frt4l66AXI8mTsBnjgwrf9Pr-y_BkEFqsOMEuwJ3DSFdmAp1eOdTxMfDQ",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:abc.com#2130bhDAK-2jKsOXJiEDG909Jux4rcYEpFsYzVlqdAY"
  }
}`

const witnessProofED25519Signature2018 = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "proof": {
      "created": "2022-03-15T21:21:54.744899145Z",
      "domain": "https://orb.domain2.com",
      "proofPurpose": "assertionMethod",
      "proofValue": "FX58osRrwU11IrUfhVTi0ucrNEq05Cv94CQNvd8SdoY66fAjwU2--m8plvxwVnXmxnlV23i6htkq4qI8qrDgAA",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:web:orb.domain2.com#orb2key"
  }
}`

const witnessProofED25519Signature2020 = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "proof": {
      "created": "2022-03-15T21:21:54.744899145Z",
      "domain": "https://orb.domain2.com",
      "proofPurpose": "assertionMethod",
      "proofValue": "FX58osRrwU11IrUfhVTi0ucrNEq05Cv94CQNvd8SdoY66fAjwU2--m8plvxwVnXmxnlV23i6htkq4qI8qrDgAA",
      "type": "Ed25519Signature2020",
      "verificationMethod": "did:web:orb.domain2.com#orb2key"
  }
}`

const witnessProofWithoutCreated = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "proof": {
    "domain": "http://orb.vct:8077",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PahivkKT6iKdnZDpkLu6uwDWYSdP7frt4l66AXI8mTsBnjgwrf9Pr-y_BkEFqsOMEuwJ3DSFdmAp1eOdTxMfDQ",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc.com#2130bhDAK-2jKsOXJiEDG909Jux4rcYEpFsYzVlqdAY"
  }
}`
