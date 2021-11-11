/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"strconv"
	"strings"
)

// WitnessPolicyConfig parses witness policy.
type WitnessPolicyConfig struct {
	MinNumberSystem int
	MinNumberBatch  int

	MinPercentSystem int
	MinPercentBatch  int

	OperatorFnc operatorFnc
	Operator    string

	LogRequired bool
}

// Gate values.
const (
	OutOf       = "OutOf"
	MinPercent  = "MinPercent"
	LogRequired = "LogRequired"

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

// Parse parses witness policy from policy string.
func Parse(policy string) (*WitnessPolicyConfig, error) {
	// default policy is 100% batch and 100% system witnesses
	wp := &WitnessPolicyConfig{
		MinPercentBatch:  maxPercent,
		MinPercentSystem: maxPercent,
		OperatorFnc:      and,
		Operator:         AND,
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

func (wp *WitnessPolicyConfig) processToken(token string) error {
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
	case t == LogRequired:
		wp.LogRequired = true
	case t == AND:
		wp.OperatorFnc = and
		wp.Operator = AND
	case t == OR:
		wp.OperatorFnc = or
		wp.Operator = OR
	default:
		return fmt.Errorf("rule not supported: %s", token)
	}

	return nil
}

// processOutOf rule (e.g. OutOf(2,system) rule means that proofs from at least 2 system witnesses are required.
func (wp *WitnessPolicyConfig) processOutOf(token string) error {
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
		wp.MinNumberSystem = minNo

		if wp.MinNumberSystem == 0 {
			wp.MinPercentSystem = 0
		}

	case RoleBatch:
		wp.MinNumberBatch = minNo

		if wp.MinNumberBatch == 0 {
			wp.MinPercentBatch = 0
		}

	default:
		return fmt.Errorf("role '%s' not supported for OutOf policy", outOfArgs[1])
	}

	return nil
}

// processMinPercent will process minimum percent rule.
// e.g. MinPercent(0.2,system) rule means that proofs from at least 20% of system witnesses are required.
func (wp *WitnessPolicyConfig) processMinPercent(token string) error {
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
		wp.MinPercentSystem = minPercent

	case RoleBatch:
		wp.MinPercentBatch = minPercent

	default:
		return fmt.Errorf("role '%s' not supported for MinPercent policy", minPercentArgs[1])
	}

	return nil
}

func (wp *WitnessPolicyConfig) String() string {
	return fmt.Sprintf("minBatch:%d, minSystem:%d, percentBatch:%d, percentSystem:%d, operator: %s, log:%t",
		wp.MinNumberBatch, wp.MinNumberSystem, wp.MinPercentBatch, wp.MinPercentSystem, wp.Operator, wp.LogRequired)
}

func and(a, b bool) bool {
	return a && b
}

func or(a, b bool) bool {
	return a || b
}
