/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"fmt"
	"time"
)

// LedgerType includes info about ledger type.
type LedgerType struct {
	Value  string
	MaxAge time.Duration
}

// CacheLifetime returns the cache lifetime of the endpoint config file before it needs to be checked for an update.
func (lt *LedgerType) CacheLifetime() (time.Duration, error) {
	return lt.MaxAge, nil
}

// ErrResourceNotFound is an error type used to indicate that a given resource could not be found.
var ErrResourceNotFound = fmt.Errorf("resource not found")
