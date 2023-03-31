/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/selector/random"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
)

// WitnessPolicy evaluates witness policy.
type WitnessPolicy struct {
	retriever   policyRetriever
	cache       gCache
	cacheExpiry time.Duration

	selector selector
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

type selector interface {
	Select(witnesses []*proof.Witness, n int) ([]*proof.Witness, error)
}

type policyRetriever interface {
	GetPolicy() (string, error)
}

// New will create new witness policy evaluator.
func New(retriever policyRetriever, policyCacheExpiry time.Duration) (*WitnessPolicy, error) {
	wp := &WitnessPolicy{
		retriever:   retriever,
		cacheExpiry: policyCacheExpiry,
		selector:    random.New(),
	}

	wp.cache = gcache.New(defaultCacheSize).ARC().LoaderExpireFunc(wp.loadWitnessPolicy).Build()

	policy, _, err := wp.loadWitnessPolicy("")
	if err != nil {
		return nil, err
	}

	err = wp.cache.SetWithExpire(WitnessPolicyKey, policy, policyCacheExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to set expiry entry in policy cache: %w", err)
	}

	logger.Debug("Created new witness policy evaluator with cache",
		logfields.WithWitnessPolicy(policy.(string)), logfields.WithCacheExpiration(policyCacheExpiry)) //nolint:forcetypeassert

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

	evaluated := cfg.OperatorFnc(batchCondition, systemCondition)

	logger.Debug("Witness policy was evaluated.",
		withPolicyConfigField(cfg), withEvaluatedField(evaluated), withBatchConditionField(batchCondition),
		withSystemConditionField(systemCondition), withWitnessProofsField(witnesses))

	return evaluated, nil
}

func (wp *WitnessPolicy) loadWitnessPolicy(interface{}) (interface{}, *time.Duration, error) {
	policy, err := wp.retriever.GetPolicy()
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil, err
	}

	logger.Debug("Loaded witness policy from store", logfields.WithWitnessPolicy(policy))

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

// Select selects min number of witnesses required based on witness policy.
func (wp *WitnessPolicy) Select(witnesses []*proof.Witness, exclude ...*proof.Witness) ([]*proof.Witness, error) {
	cfg, err := wp.getWitnessPolicyConfig()
	if err != nil {
		return nil, err
	}

	selectedBatchWitnesses, selectedSystemWitnesses, err := wp.selectBatchAndSystemWitnesses(witnesses, cfg, exclude...)
	if err != nil {
		return nil, err
	}

	if cfg.Operator == config.AND {
		return append(selectedBatchWitnesses, selectedSystemWitnesses...), nil
	}

	if len(selectedBatchWitnesses) == 0 || len(selectedSystemWitnesses) < len(selectedBatchWitnesses) {
		return selectedSystemWitnesses, nil
	}

	return selectedBatchWitnesses, nil
}

// selects min number of batch and system witnesses that are required to fulfill witness policy.
//
//nolint:cyclop
func (wp *WitnessPolicy) selectBatchAndSystemWitnesses(witnesses []*proof.Witness,
	cfg *config.WitnessPolicyConfig, exclude ...*proof.Witness,
) ([]*proof.Witness, []*proof.Witness, error) {
	logger.Debug("Selecting minimum number of batch and system witnesses based on policy",
		withPolicyConfigField(cfg), withWitnessesField(witnesses))

	var eligibleBatchWitnesses []*proof.Witness

	var eligibleSystemWitnesses []*proof.Witness

	totalSystemWitnesses := 0
	totalBatchWitnesses := 0

	for _, w := range witnesses {
		logOK := checkLog(cfg.LogRequired, w.HasLog)

		switch w.Type {
		case proof.WitnessTypeBatch:
			totalBatchWitnesses++

			if logOK && !isExcluded(w, exclude...) {
				eligibleBatchWitnesses = append(eligibleBatchWitnesses, w)
			}

		case proof.WitnessTypeSystem:
			totalSystemWitnesses++

			if logOK && !isExcluded(w, exclude...) {
				eligibleSystemWitnesses = append(eligibleSystemWitnesses, w)
			}
		}
	}

	logger.Debug("Selecting minimum number of witnesses based on policy and eligible batch and system witnesses",
		withPolicyConfigField(cfg), withBatchWitnessesField(eligibleBatchWitnesses),
		withSystemWitnessesField(eligibleSystemWitnesses))

	var selectedBatchWitnesses []*proof.Witness

	var commonWitnesses []*proof.Witness

	if cfg.Operator == config.AND {
		commonWitnesses = intersection(eligibleBatchWitnesses, eligibleSystemWitnesses)
	}

	// it is possible to have 0 zero eligible batch witnesses
	if len(eligibleBatchWitnesses) != 0 {
		var err error

		selectedBatchWitnesses, err = wp.selectMinWitnesses(eligibleBatchWitnesses, cfg.MinNumberBatch,
			cfg.MinPercentBatch, totalBatchWitnesses, commonWitnesses...)
		if err != nil {
			return nil, nil, fmt.Errorf("select batch witnesses based on witnesses%s, eligible%s, exclude%s common%s, total[%d], policy[%s]: %w",
				witnesses, eligibleBatchWitnesses, exclude, commonWitnesses, totalBatchWitnesses, cfg, err)
		}
	}

	logger.Debug("Selected batch witnesses", logfields.WithTotal(len(selectedBatchWitnesses)),
		withBatchWitnessesField(selectedBatchWitnesses))

	selectedSystemWitnesses, err := wp.selectMinWitnesses(eligibleSystemWitnesses, cfg.MinNumberSystem,
		cfg.MinPercentSystem, totalSystemWitnesses, commonWitnesses...)
	if err != nil {
		return nil, nil, fmt.Errorf("select system witnesses based on witnesses%s, eligible%s, common%s, total[%d], policy[%s]: %w",
			witnesses, eligibleSystemWitnesses, commonWitnesses, totalSystemWitnesses, cfg, err)
	}

	logger.Debug("Selected system witnesses", logfields.WithTotal(len(selectedSystemWitnesses)),
		withSystemWitnessesField(selectedSystemWitnesses))

	return selectedBatchWitnesses, selectedSystemWitnesses, nil
}

func isExcluded(witness *proof.Witness, excluded ...*proof.Witness) bool {
	for _, e := range excluded {
		if witness.URI.String() == e.URI.String() {
			return true
		}
	}

	return false
}

func (wp *WitnessPolicy) selectMinWitnesses(eligible []*proof.Witness, minNumber, minPercent,
	totalWitnesses int, preferred ...*proof.Witness,
) ([]*proof.Witness, error) {
	var selected []*proof.Witness
	selected = append(selected, preferred...)

	minSelection := len(eligible) - len(preferred)

	if minNumber > 0 {
		minSelection = minNumber - len(preferred)
	} else if minPercent >= 0 {
		minSelection = int(math.Ceil(float64(minPercent)/maxPercent*float64(totalWitnesses))) - len(preferred)
	}

	logger.Debug("Selecting witnesses from eligible and preferred", logfields.WithMinimum(minSelection),
		withEligibleWitnessesField(eligible), withPreferredWitnessesField(preferred))

	selection, err := wp.selector.Select(difference(eligible, preferred), minSelection)
	if err != nil {
		return nil, err
	}

	selected = append(selected, selection...)

	return selected, nil
}

func intersection(a, b []*proof.Witness) []*proof.Witness {
	var result []*proof.Witness

	hash := make(map[string]bool)
	for _, e := range a {
		hash[e.URI.String()] = false
	}

	for _, e := range b {
		if v, ok := hash[e.URI.String()]; ok && !v {
			result = append(result, e)
			hash[e.URI.String()] = true
		}
	}

	return result
}

func difference(a, b []*proof.Witness) []*proof.Witness {
	var result []*proof.Witness

	hash := make(map[string]bool)
	for _, e := range b {
		hash[e.URI.String()] = true
	}

	for _, e := range a {
		if _, ok := hash[e.URI.String()]; !ok {
			result = append(result, e)
		}
	}

	return result
}
