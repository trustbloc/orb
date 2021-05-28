/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/trustbloc/orb/pkg/anchor/proof"
)

// WitnessPolicy evaluates witness policy.
type WitnessPolicy struct {
	minNumberSystem int
	minNumberBatch  int

	minPercentSystem int
	minPercentBatch  int

	operator operatorFnc
}

// Gate values.
const (
	OutOf      = "OutOf"
	MinPercent = "MinPercent"

	AND = "AND"
	OR  = "OR"
)

// Role values.
const (
	RoleBatch  = "batch"
	RoleSystem = "system"
)

const maxPercent = 100

type operatorFnc func(a, b bool) bool

// New parses witness policy from policy string.
func New(policy string) (*WitnessPolicy, error) {
	// default policy is 100% batch and 100% system witnesses
	wp := &WitnessPolicy{
		minPercentBatch:  maxPercent,
		minPercentSystem: maxPercent,
		operator:         and,
	}

	if policy == "" {
		return wp, nil
	}

	tokens := strings.Split(policy, " ")

	for _, token := range tokens {
		err := wp.processToken(token)
		if err != nil {
			return nil, err
		}
	}

	return wp, nil
}

func (wp *WitnessPolicy) processToken(token string) error {
	switch t := token; {
	case strings.HasPrefix(t, OutOf):
		err := wp.processOutOf(token)
		if err != nil {
			return err
		}
	case strings.HasPrefix(t, MinPercent):
		err := wp.processMinPercent(token)
		if err != nil {
			return err
		}
	case t == AND:
		wp.operator = and
	case t == OR:
		wp.operator = or
	default:
		return fmt.Errorf("rule not supported: %s", token)
	}

	return nil
}

// processOutOf rule (e.g. OutOf(2,system) rule means that proofs from at least 2 system witnesses are required.
func (wp *WitnessPolicy) processOutOf(token string) error {
	insideBrackets := token[len(OutOf)+1 : len(token)-1]

	outOfArgs := strings.Split(insideBrackets, ",")

	const outOfArgsNo = 2
	if len(outOfArgs) != outOfArgsNo {
		return fmt.Errorf("expected 2 but got %d arguments for OutOf policy", len(outOfArgs))
	}

	minNo, err := strconv.Atoi(outOfArgs[0])
	if err != nil {
		return fmt.Errorf("first argument for OutOf policy must be an integer: %w", err)
	}

	switch outOfArgs[1] {
	case RoleSystem:
		wp.minNumberSystem = minNo

	case RoleBatch:
		wp.minNumberBatch = minNo

	default:
		return fmt.Errorf("role '%s' not supported for OutOf policy", outOfArgs[1])
	}

	return nil
}

// processMinPercent will process minimum percent rule.
// e.g. MinPercent(0.2,system) rule means that proofs from at least 20% of system witnesses are required.
func (wp *WitnessPolicy) processMinPercent(token string) error {
	insideBrackets := token[len(MinPercent)+1 : len(token)-1]

	minPercentArgs := strings.Split(insideBrackets, ",")

	const minPercentArgsNo = 2
	if len(minPercentArgs) != minPercentArgsNo {
		return fmt.Errorf("expected 2 but got %d arguments for MinPercent policy", len(minPercentArgs))
	}

	minPercent, err := strconv.Atoi(minPercentArgs[0])
	if err != nil {
		return fmt.Errorf("first argument for OutOf policy must be an integer between 0 and 100: %w", err)
	}

	if minPercent < 0 || minPercent > 100 {
		return fmt.Errorf("first argument for OutOf policy must be an integer between 0 and 100")
	}

	switch minPercentArgs[1] {
	case RoleSystem:
		wp.minPercentSystem = minPercent

	case RoleBatch:
		wp.minPercentBatch = minPercent

	default:
		return fmt.Errorf("role '%s' not supported for MinPercent policy", minPercentArgs[1])
	}

	return nil
}

// Evaluate evaluates if witness policy has been satisfied for provided witnesses.
func (wp *WitnessPolicy) Evaluate(witnesses []*proof.WitnessProof) (bool, error) {
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

	batchCondition := evaluate(collectedBatchWitnesses, totalBatchWitnesses, wp.minNumberBatch, wp.minPercentBatch)
	systemCondition := evaluate(collectedSystemWitnesses, totalSystemWitnesses, wp.minNumberSystem, wp.minPercentSystem)

	return wp.operator(batchCondition, systemCondition), nil
}

func evaluate(collected, total, minNumber, minPercent int) bool {
	percentCollected := 100
	if total != 0 {
		percentCollected = collected / total
	}

	return (minNumber != 0 && collected >= minNumber) ||
		percentCollected >= minPercent/maxPercent
}

func and(a, b bool) bool {
	return a && b
}

func or(a, b bool) bool {
	return a || b
}
