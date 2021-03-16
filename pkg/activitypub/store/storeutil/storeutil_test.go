/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storeutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

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
