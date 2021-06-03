/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"errors"
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/anchor/policy/config"
	"github.com/trustbloc/orb/pkg/anchor/proof"
)

// WitnessPolicy evaluates witness policy.
type WitnessPolicy struct {
	configStore storage.Store
	cache       gCache
	cacheExpiry time.Duration
}

const (
	maxPercent = 100

	policyKey = "witness-policy"

	defaultCacheSize = 10
)

var logger = log.New("witness-policy")

type gCache interface {
	Get(key interface{}) (interface{}, error)
	SetWithExpire(interface{}, interface{}, time.Duration) error
}

// New parses witness policy from policy string.
func New(configStore storage.Store, policyCacheExpiry time.Duration) (*WitnessPolicy, error) {
	wp := &WitnessPolicy{
		configStore: configStore,
		cacheExpiry: policyCacheExpiry,
	}

	wp.cache = gcache.New(defaultCacheSize).ARC().LoaderExpireFunc(wp.loadWitnessPolicy).Build()

	policy, _, err := wp.loadWitnessPolicy(policyKey)
	if err != nil {
		return nil, err
	}

	err = wp.cache.SetWithExpire(policyKey, policy, policyCacheExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to set expiry entry in policy cache: %w", err)
	}

	return wp, nil
}

// Evaluate evaluates if witness policy has been satisfied for provided witnesses.
func (wp *WitnessPolicy) Evaluate(witnesses []*proof.WitnessProof) (bool, error) {
	cfg, err := wp.getWitnessPolicyConfig()
	if err != nil {
		return false, err
	}

	totalSystemWitnesses := 0
	collectedSystemWitnesses := 0

	totalBatchWitnesses := 0
	collectedBatchWitnesses := 0

	for _, w := range witnesses {
		switch w.Type {
		case proof.WitnessTypeBatch:
			totalBatchWitnesses++

			if w.Proof != nil {
				collectedBatchWitnesses++
			}

		case proof.WitnessTypeSystem:
			totalSystemWitnesses++

			if w.Proof != nil {
				collectedSystemWitnesses++
			}
		}
	}

	batchCondition := evaluate(collectedBatchWitnesses, totalBatchWitnesses, cfg.MinNumberBatch, cfg.MinPercentBatch)
	systemCondition := evaluate(collectedSystemWitnesses, totalSystemWitnesses, cfg.MinNumberSystem, cfg.MinPercentSystem)

	return cfg.Operator(batchCondition, systemCondition), nil
}

func (wp *WitnessPolicy) loadWitnessPolicy(key interface{}) (interface{}, *time.Duration, error) {
	witnessPolicy, err := wp.configStore.Get(key.(string))
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil, err
	}

	policy := ""
	if witnessPolicy != nil {
		policy = string(witnessPolicy)
	}

	logger.Debugf("loaded witness policy from store: %s", policy)

	return policy, &wp.cacheExpiry, nil
}

func (wp *WitnessPolicy) getWitnessPolicyConfig() (*config.WitnessPolicyConfig, error) {
	value, err := wp.cache.Get(policyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policy from policy cache: %w", err)
	}

	if value == nil {
		return nil, fmt.Errorf("failed to retrieve policy from policy cache (nil value)")
	}

	policy, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected interface '%T' for witness policy value in policy cache", value)
	}

	policyCfg, err := config.Parse(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy config from policy[%s]: %w", policy, err)
	}

	return policyCfg, nil
}

func evaluate(collected, total, minNumber, minPercent int) bool {
	percentCollected := 100
	if total != 0 {
		percentCollected = collected / total
	}

	return (minNumber != 0 && collected >= minNumber) ||
		percentCollected >= minPercent/maxPercent
}
