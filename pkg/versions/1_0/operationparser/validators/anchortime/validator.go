/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchortime

import (
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
)

// New creates new anchor time validator.
func New(maxDelta uint64) *Validator {
	return &Validator{maxDelta: maxDelta}
}

// Validator is used to validate anchor times (from, until) against server time.
type Validator struct {
	maxDelta uint64
}

// Validate validates anchor times (from and until) against current time.
func (v *Validator) Validate(from, until int64) error {
	if from == 0 && until == 0 {
		// from and until are not specified - no error
		return nil
	}

	serverTime := time.Now().Unix()

	if from > serverTime {
		return operationparser.ErrOperationEarly
	}

	if v.getAnchorUntil(from, until) <= serverTime {
		return operationparser.ErrOperationExpired
	}

	return nil
}

func (v *Validator) getAnchorUntil(from, until int64) int64 {
	if from != 0 && until == 0 {
		return from + int64(v.maxDelta)
	}

	return until
}
