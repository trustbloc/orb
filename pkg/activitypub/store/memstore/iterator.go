/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"net/url"

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

func (it *iterator) TotalItems() (int, error) {
	return it.totalItems, nil
}

func (it *iterator) Close() error {
	return nil
}

// ActivityIterator is used to iterator over activities.
type ActivityIterator struct {
	*iterator
	results []*vocab.ActivityType
}

// NewActivityIterator creates a new ActivityIterator.
func NewActivityIterator(results []*vocab.ActivityType, totalItems int) *ActivityIterator {
	return &ActivityIterator{
		iterator: newIterator(totalItems),
		results:  results,
	}
}

// Next returns the next activity or an ErrNotFound error if there are no more items.
func (it *ActivityIterator) Next() (*vocab.ActivityType, error) {
	if it.current >= len(it.results)-1 {
		return nil, spi.ErrNotFound
	}

	it.current++

	return it.results[it.current], nil
}

// ReferenceIterator is used to iterator over references.
type ReferenceIterator struct {
	*iterator
	results []*url.URL
}

// NewReferenceIterator creates a new ReferenceIterator.
func NewReferenceIterator(results []*url.URL, totalItems int) *ReferenceIterator {
	return &ReferenceIterator{
		iterator: newIterator(totalItems),
		results:  results,
	}
}

// Next returns the next reference or an ErrNotFound error if there are no more items.
func (it *ReferenceIterator) Next() (*url.URL, error) {
	if it.current >= len(it.results)-1 {
		return nil, spi.ErrNotFound
	}

	it.current++

	return it.results[it.current], nil
}
