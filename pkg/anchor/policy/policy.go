/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"encoding/json"
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
	// WitnessPolicyKey is witness policy key in config store.
	WitnessPolicyKey = "witness-policy"

	maxPercent = 100

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

	policy, _, err := wp.loadWitnessPolicy(WitnessPolicyKey)
	if err != nil {
		return nil, err
	}

	err = wp.cache.SetWithExpire(WitnessPolicyKey, policy, policyCacheExpiry)
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
		logOK := checkLog(cfg.LogRequired, w.HasLog)

		switch w.Type {
		case proof.WitnessTypeBatch:
			totalBatchWitnesses++

			if logOK && w.Proof != nil {
				collectedBatchWitnesses++
			}

		case proof.WitnessTypeSystem:
			totalSystemWitnesses++

			if logOK && w.Proof != nil {
				collectedSystemWitnesses++
			}
		}
	}

	batchCondition := evaluate(collectedBatchWitnesses, totalBatchWitnesses, cfg.MinNumberBatch, cfg.MinPercentBatch)
	systemCondition := evaluate(collectedSystemWitnesses, totalSystemWitnesses, cfg.MinNumberSystem, cfg.MinPercentSystem)

	evaluated := cfg.Operator(batchCondition, systemCondition)

	logger.Debugf("witness policy[%s] evaluated to[%t] with batch[%t] and system[%t] for witnesses: %s",
		cfg, evaluated, batchCondition, systemCondition, witnesses)

	return evaluated, nil
}

func (wp *WitnessPolicy) loadWitnessPolicy(key interface{}) (interface{}, *time.Duration, error) {
	witnessPolicy, err := wp.configStore.Get(key.(string))
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil, err
	}

	var policy string

	if len(witnessPolicy) != 0 {
		if err := json.Unmarshal(witnessPolicy, &policy); err != nil {
			return nil, nil, fmt.Errorf("unmarshal policy error: %w", err)
		}
	}

	logger.Debugf("loaded witness policy from store: %s", policy)

	return policy, &wp.cacheExpiry, nil
}

func (wp *WitnessPolicy) getWitnessPolicyConfig() (*config.WitnessPolicyConfig, error) {
	value, err := wp.cache.Get(WitnessPolicyKey)
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
	percentCollected := float64(maxPercent)
	if total != 0 {
		percentCollected = float64(collected) / float64(total)
	}

	return (minNumber != 0 && collected >= minNumber) ||
		percentCollected >= float64(minPercent)/maxPercent
}

func checkLog(logRequired, hasLog bool) bool {
	if logRequired {
		return hasLog
	}

	// log is not required, witness without log is counted for policy
	return true
}
