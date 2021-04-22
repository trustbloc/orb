/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"
	"net/url"
)

// ReadReferences reads the references from the given iterator up to a maximum number
// specified by maxItems. If maxItems <= 0 then all references are read.
func ReadReferences(it ReferenceIterator, maxItems int) ([]*url.URL, error) {
	var refs []*url.URL

	for maxItems <= 0 || len(refs) < maxItems {
		ref, err := it.Next()
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				break
			}

			return nil, err
		}

		refs = append(refs, ref)
	}

	return refs, nil
}
