/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storeutil

import (
	"net/url"

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

// ReadReferences returns all of the references resulting from iterating over the given iterator,
// up to the given maximum number of references. If maxItems is <=0 then all items are read.
func ReadReferences(it store.ReferenceIterator, maxItems int) ([]*url.URL, error) {
	var refs []*url.URL

	for i := 0; maxItems <= 0 || i < maxItems; i++ {
		ref, err := it.Next()
		if err != nil {
			if err == store.ErrNotFound {
				break
			}

			return nil, err
		}

		refs = append(refs, ref)
	}

	return refs, nil
}
