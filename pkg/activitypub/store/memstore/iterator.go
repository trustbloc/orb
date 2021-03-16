/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

type iterator struct {
	current    int
	totalItems int
}

func newIterator(totalItems int) *iterator {
	return &iterator{
		totalItems: totalItems,
		current:    -1,
	}
}

func (it *iterator) TotalItems() int {
	return it.totalItems
}

func (it *iterator) Close() {
}

type activityIterator struct {
	*iterator
	results []*vocab.ActivityType
}

func newActivityIterator(results []*vocab.ActivityType, totalItems int) *activityIterator {
	return &activityIterator{
		iterator: newIterator(totalItems),
		results:  results,
	}
}

func (it *activityIterator) Next() (*vocab.ActivityType, error) {
	if it.current >= len(it.results)-1 {
		return nil, spi.ErrNotFound
	}

	it.current++

	return it.results[it.current], nil
}
