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
	results []*vocab.ActivityType
	current int
}

func newIterator(results []*vocab.ActivityType) *iterator {
	return &iterator{
		results: results,
		current: -1,
	}
}

func (it *iterator) Next() (*vocab.ActivityType, error) {
	if it.current >= len(it.results)-1 {
		return nil, spi.ErrNotFound
	}

	it.current++

	return it.results[it.current], nil
}

func (it *iterator) Close() {
}
