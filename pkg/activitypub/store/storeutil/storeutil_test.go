/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storeutil

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

//go:generate counterfeiter -o ../mocks/referenceiterator.gen.go --fake-name ReferenceIterator ../spi ReferenceIterator

func TestGetQueryOptions(t *testing.T) {
	options := GetQueryOptions(
		spi.WithPageNum(1),
		spi.WithSortOrder(spi.SortDescending),
		spi.WithPageSize(10),
	)
	require.NotNil(t, options)
	require.Equal(t, 1, options.PageNumber)
	require.Equal(t, 10, options.PageSize)
	require.Equal(t, spi.SortDescending, options.SortOrder)
}

func TestReadReferences(t *testing.T) {
	url1, err := url.Parse("https://url1")
	require.NoError(t, err)

	url2, err := url.Parse("https://url2")
	require.NoError(t, err)

	url3, err := url.Parse("https://url3")
	require.NoError(t, err)

	t.Run("All items", func(t *testing.T) {
		it := &mocks.ReferenceIterator{}

		it.NextReturnsOnCall(0, url1, nil)
		it.NextReturnsOnCall(1, url2, nil)
		it.NextReturnsOnCall(2, url3, nil)
		it.NextReturnsOnCall(3, nil, spi.ErrNotFound)

		refs, err := ReadReferences(it, 5)
		require.NoError(t, err)
		require.Len(t, refs, 3)
		require.Equal(t, url1.String(), refs[0].String())
		require.Equal(t, url2.String(), refs[1].String())
		require.Equal(t, url3.String(), refs[2].String())
	})

	t.Run("Max items reached", func(t *testing.T) {
		it := &mocks.ReferenceIterator{}

		it.NextReturnsOnCall(0, url1, nil)
		it.NextReturnsOnCall(1, url2, nil)
		it.NextReturnsOnCall(2, url3, nil)
		it.NextReturnsOnCall(3, nil, spi.ErrNotFound)

		refs, err := ReadReferences(it, 1)
		require.NoError(t, err)
		require.Len(t, refs, 1)
		require.Equal(t, url1.String(), refs[0].String())
	})

	t.Run("Iterator error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected iterator error")

		it := &mocks.ReferenceIterator{}

		it.NextReturns(nil, errExpected)

		refs, err := ReadReferences(it, 1)
		require.EqualError(t, err, errExpected.Error())
		require.Empty(t, refs)
	})
}
