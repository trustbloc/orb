/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	defaultPolicyCacheExpiry = 5 * time.Second
	configStoreName          = "orb-config"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)
	})

	t.Run("success - call to cache loader function", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, 1*time.Second)
		require.NoError(t, err)
		require.NotNil(t, wp)

		err = configStore.Put(WitnessPolicyKey, []byte("MinPercent(30,system) AND MinPercent(70,batch)"))
		require.NoError(t, err)

		time.Sleep(2 * time.Second)
	})

	t.Run("error - config store error", func(t *testing.T) {
		configStore := &storemocks.Store{}
		configStore.GetReturns(nil, fmt.Errorf("get error"))

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.Error(t, err)
		require.Nil(t, wp)
		require.Contains(t, err.Error(), "get error")
	})
}

func TestEvaluate(t *testing.T) {
	witnessURL, err := url.Parse("https://domain.com/service")
	require.NoError(t, err)

	batchWitnessURL, err := url.Parse("https://batch.com/service")
	require.NoError(t, err)

	systemWitnessURL, err := url.Parse("https://system.com/service")
	require.NoError(t, err)

	batchWitness2URL, err := url.Parse("https://other.batch.com/service")
	require.NoError(t, err)

	systemWitness2URL, err := url.Parse("https://other.system.com/service")
	require.NoError(t, err)

	t.Run("success - default policy satisfied (100% batch and 100% system)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   witnessURL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   witnessURL,
				Proof: []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - default policy(100% batch and 100% system) satisfied with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - default policy fails with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy(50% batch and 50% system) satisfied with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,batch) AND MinPercent(50,system) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitness2URL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness2URL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy policy(50% batch and 50% system) fails with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,batch) AND MinPercent(50,system) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy OutOf(OR) satisfied with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system) OR OutOf(1,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy OutOf(AND) satisfied with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system) AND OutOf(1,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy OutOf(AND) fails with log required", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system) AND OutOf(1,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				Proof:  []byte("proof"),
				HasLog: false,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				Proof:  []byte("proof"),
				HasLog: true,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy not satisfied (no proofs)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitnessURL,
			},
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitness2URL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy not satisfied (no system proofs)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitness2URL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy satisfied (all batch witness proofs(default), one system witness proof)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system)"`))
		require.NoError(t, err)

		wp, err := New(configStore, 1*time.Second)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitness2URL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   systemWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs, 50% system witness proofs)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) AND MinPercent(50,batch)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitness2URL,
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   systemWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs or 50% system witness proofs)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) OR MinPercent(50,batch)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitness2URL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs or 50% system witness proofs)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) OR MinPercent(50,batch)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitness2URL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (all batch witness proofs(default), one system witness proof)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitness2URL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   systemWitnessURL,
				Proof: []byte("proof"),
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitness2URL,
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - no system witnesses provided", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) AND MinPercent(50,batch)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   batchWitnessURL,
				Proof: []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - no batch witnesses provided", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) AND MinPercent(50,batch)"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeSystem,
				URI:   systemWitnessURL,
				Proof: []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - update policy in the config store (policy change test)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(0,batch) AND OutOf(1,system)"`))
		require.NoError(t, err)

		wp, err := New(configStore, 1*time.Second)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitnessURL,
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   systemWitnessURL,
				Proof: []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)

		// change policy to 1 system witness and 1 batch witness
		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,batch) AND OutOf(1,system)"`))
		require.NoError(t, err)

		// wait for cache to refresh entry
		time.Sleep(2 * time.Second)

		// policy should return false since there is not enough system proofs
		ok, err = wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)

		witnessProofs[0].Proof = []byte("added proof")
		ok, err = wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("error - get policy from cache error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		wp.cache = &mockCache{GetErr: fmt.Errorf("get policy from cache error")}

		witnessProofs := []*proof.WitnessProof{
			{
				Type:  proof.WitnessTypeBatch,
				URI:   witnessURL,
				Proof: []byte("proof"),
			},
			{
				Type:  proof.WitnessTypeSystem,
				URI:   witnessURL,
				Proof: []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.Error(t, err)
		require.Equal(t, false, ok)
		require.Contains(t, err.Error(), "failed to retrieve policy from policy cache: get policy from cache error")
	})
}

func TestGetWitnessPolicyConfig(t *testing.T) {
	t.Run("success - policy config retrieved from the cache", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		cfg, err := wp.getWitnessPolicyConfig()
		require.NoError(t, err)
		require.NotNil(t, cfg)
	})

	t.Run("error - failed to retrieve policy from policy cache (nil value)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		wp.cache = &mockCache{}

		cfg, err := wp.getWitnessPolicyConfig()
		require.Error(t, err)
		require.Nil(t, cfg)
		require.Contains(t, err.Error(), "failed to retrieve policy from policy cache (nil value)")
	})

	t.Run("error - get witness policy from cache error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		wp.cache = &mockCache{GetErr: fmt.Errorf("get error")}

		cfg, err := wp.getWitnessPolicyConfig()
		require.Error(t, err)
		require.Nil(t, cfg)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("error - unexpected interface for witness policy value", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		wp.cache = &mockCache{GetValue: []byte("not string")}

		cfg, err := wp.getWitnessPolicyConfig()
		require.Error(t, err)
		require.Nil(t, cfg)
		require.Contains(t, err.Error(),
			"unexpected interface '[]uint8' for witness policy value in policy cache")
	})

	t.Run("error - parse witness policy error (rule not supported)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		// rule not supported - parse fails
		wp.cache = &mockCache{GetValue: "Test(a,b)"}

		cfg, err := wp.getWitnessPolicyConfig()
		require.Error(t, err)
		require.Nil(t, cfg)
		require.Contains(t, err.Error(), "rule not supported: Test(a,b)")
	})

	t.Run("error - failed to unmarshal policy", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte("invalid JSON string"))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal policy error")
		require.Nil(t, wp)
	})
}

func TestSelect(t *testing.T) {
	batchWitnessURL, err := url.Parse("https://batch.com/service")
	require.NoError(t, err)

	systemWitnessURL, err := url.Parse("https://system.com/service")
	require.NoError(t, err)

	batchWitness2URL, err := url.Parse("https://second.batch.com/service")
	require.NoError(t, err)

	systemWitness2URL, err := url.Parse("https://second.system.com/service")
	require.NoError(t, err)

	systemWitness3URL, err := url.Parse("https://third.system.com/service")
	require.NoError(t, err)

	t.Run("success - default policy (AND)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 2, len(selected))
		require.Equal(t, "https://batch.com/service", selected[0].URI.String())
		require.Equal(t, "https://system.com/service", selected[1].URI.String())
	})

	t.Run("success - default policy (AND) plus common witnesses", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  batchWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  batchWitnessURL,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 3, len(selected))
	})

	t.Run("success - zero eligible batch witnesses", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 1, len(selected))
		require.Equal(t, "https://system.com/service", selected[0].URI.String())
	})

	t.Run("success - policy with AND and minimum percent", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) AND MinPercent(50,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness2URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness3URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitness2URL,
				HasLog: false,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 3, len(selected))
		require.Equal(t, "https://batch.com/service", selected[0].URI.String())
	})

	t.Run("success - policy with AND and OutOf", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(2,system) AND OutOf(1,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness2URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness3URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitness2URL,
				HasLog: false,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 3, len(selected))
		require.Equal(t, "https://batch.com/service", selected[0].URI.String())
	})

	t.Run("success - policy with OR (batch witnesses selected)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) OR MinPercent(50,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness2URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitness3URL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitness2URL,
				HasLog: false,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 1, len(selected))
		require.Equal(t, "https://batch.com/service", selected[0].URI.String())
	})

	t.Run("success - policy with OR (system witnesses selected)", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"MinPercent(50,system) OR MinPercent(50,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
		}

		selected, err := wp.Select(witnesses)
		require.NoError(t, err)
		require.Equal(t, 1, len(selected))
		require.Equal(t, "https://system.com/service", selected[0].URI.String())
	})

	t.Run("error - number of eligible system witnesses doesn't meet policy requirements", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(2,system) AND OutOf(1,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				HasLog: true,
			},
		}

		selected, err := wp.Select(witnesses)
		require.Error(t, err)
		require.Nil(t, selected)
		require.Contains(t, err.Error(),
			"select system witnesses as per policy: unable to select 2 witnesses from witness array of length 1")
	})

	t.Run("error - number of eligible batch witnesses doesn't meet policy requirements", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		err = configStore.Put(WitnessPolicyKey, []byte(`"OutOf(1,system) AND OutOf(2,batch) LogRequired"`))
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnesses := []*proof.Witness{
			{
				Type:   proof.WitnessTypeSystem,
				URI:    systemWitnessURL,
				HasLog: true,
			},
			{
				Type:   proof.WitnessTypeBatch,
				URI:    batchWitnessURL,
				HasLog: true,
			},
		}

		selected, err := wp.Select(witnesses)
		require.Error(t, err)
		require.Nil(t, selected)
		require.Contains(t, err.Error(),
			"select batch witnesses as per policy: unable to select 2 witnesses from witness array of length 1")
	})

	t.Run("error - get policy from cache error", func(t *testing.T) {
		configStore, err := mem.NewProvider().OpenStore(configStoreName)
		require.NoError(t, err)

		wp, err := New(configStore, defaultPolicyCacheExpiry)
		require.NoError(t, err)
		require.NotNil(t, wp)

		wp.cache = &mockCache{GetErr: fmt.Errorf("get policy from cache error")}

		witnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  systemWitnessURL,
			},
		}

		selected, err := wp.Select(witnesses)
		require.Error(t, err)
		require.Nil(t, selected)
		require.Contains(t, err.Error(), "failed to retrieve policy from policy cache: get policy from cache error")
	})
}

func TestIntersection(t *testing.T) {
	witnessURL, err := url.Parse("https://witness.com/service")
	require.NoError(t, err)

	otherWitnessURL, err := url.Parse("https://other.witness.com/service")
	require.NoError(t, err)

	t.Run("success - no common elements", func(t *testing.T) {
		batchWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  witnessURL,
			},
		}
		systemWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  otherWitnessURL,
			},
		}

		intersect := intersection(batchWitnesses, systemWitnesses)
		require.Equal(t, 0, len(intersect))
	})

	t.Run("success - common elements", func(t *testing.T) {
		batchWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  witnessURL,
			},
		}
		systemWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  witnessURL,
			},
		}

		intersect := intersection(batchWitnesses, systemWitnesses)
		require.Equal(t, 1, len(intersect))
	})

	t.Run("success - common elements (no duplicates)", func(t *testing.T) {
		batchWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  witnessURL,
			},
		}
		systemWitnesses := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  witnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  witnessURL,
			},
		}

		intersect := intersection(batchWitnesses, systemWitnesses)
		require.Equal(t, 1, len(intersect))
	})
}

func TestDifference(t *testing.T) {
	witnessURL, err := url.Parse("https://witness.com/service")
	require.NoError(t, err)

	otherWitnessURL, err := url.Parse("https://other.witness.com/service")
	require.NoError(t, err)

	t.Run("success - additional element in eligible", func(t *testing.T) {
		eligible := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  witnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  otherWitnessURL,
			},
		}

		preferred := []*proof.Witness{
			{
				Type: proof.WitnessTypeSystem,
				URI:  otherWitnessURL,
			},
		}

		diff := difference(eligible, preferred)
		require.Equal(t, 1, len(diff))
		require.Equal(t, "https://witness.com/service", diff[0].URI.String())
	})

	t.Run("success - preferred not provided", func(t *testing.T) {
		eligible := []*proof.Witness{
			{
				Type: proof.WitnessTypeBatch,
				URI:  witnessURL,
			},
			{
				Type: proof.WitnessTypeSystem,
				URI:  otherWitnessURL,
			},
		}

		diff := difference(eligible, nil)
		require.Equal(t, len(eligible), len(diff))
		require.Equal(t, diff, eligible)
	})

	t.Run("success - eligible not provided either", func(t *testing.T) {
		diff := difference(nil, nil)
		require.Equal(t, 0, len(diff))
	})
}

type mockCache struct {
	GetErr   error
	SetErr   error
	GetValue interface{}
}

func (mc *mockCache) Get(interface{}) (interface{}, error) {
	if mc.GetErr != nil {
		return nil, mc.GetErr
	}

	return mc.GetValue, nil
}

func (mc *mockCache) SetWithExpire(interface{}, interface{}, time.Duration) error {
	if mc.SetErr != nil {
		return mc.SetErr
	}

	return nil
}
