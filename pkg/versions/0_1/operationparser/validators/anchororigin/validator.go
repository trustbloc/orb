/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchororigin

import "fmt"

// New creates anchor origin validator.
func New(allowed []string) *Validator {
	return &Validator{allowed: sliceToMap(allowed)}
}

// Validator is anchor origin validator.
type Validator struct {
	allowed map[string]bool
}

// Validate validates anchor origin object.
func (v *Validator) Validate(obj interface{}) error {
	if obj == nil {
		return nil
	}

	// if allowed origins contains wild-card '*' any origin is allowed
	_, ok := v.allowed["*"]
	if ok {
		return nil
	}

	var val string

	switch t := obj.(type) {
	case string:
		val, _ = obj.(string) // nolint: errcheck
	default:
		return fmt.Errorf("anchor origin type not supported %T", t)
	}

	_, ok = v.allowed[val]
	if !ok {
		return fmt.Errorf("origin %s is not supported", val)
	}

	return nil
}

func sliceToMap(ids []string) map[string]bool {
	// convert slice to map
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}
