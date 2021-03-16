/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storeutil

import (
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

// GetQueryOptions populates and returns the QueryOptions struct with the given options.
func GetQueryOptions(opts ...store.QueryOpt) *store.QueryOptions {
	options := &store.QueryOptions{
		PageNumber: -1,
		PageSize:   -1,
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}
