/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestActivityIterator(t *testing.T) {
	var (
		activityID1 = testutil.MustParseURL("https://example.com/activities/activity1")
		activityID2 = testutil.MustParseURL("https://example.com/activities/activity2")
	)

	activity1 := vocab.NewAnnounceActivity(vocab.NewObjectProperty(), vocab.WithID(activityID1))
	activity2 := vocab.NewAnnounceActivity(vocab.NewObjectProperty(), vocab.WithID(activityID2))

	results := []*vocab.ActivityType{activity1, activity2}

	it := NewActivityIterator(results, 5)
	require.NotNil(t, it)

	totalItems, err := it.TotalItems()
	require.NoError(t, err)
	require.Equal(t, 5, totalItems)

	a, err := it.Next()
	require.NoError(t, err)
	require.NotNil(t, a)
	require.True(t, a.ID().String() == activityID1.String())

	a, err = it.Next()
	require.NoError(t, err)
	require.NotNil(t, a)
	require.True(t, a.ID().String() == activityID2.String())

	a, err = it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)

	require.NoError(t, it.Close())
}

func TestReferenceIterator(t *testing.T) {
	ref1 := testutil.MustParseURL("https://ref_1")
	ref2 := testutil.MustParseURL("https://ref_2")

	results := []*url.URL{ref1, ref2}

	it := NewReferenceIterator(results, 5)
	require.NotNil(t, it)

	totalItems, err := it.TotalItems()
	require.NoError(t, err)
	require.Equal(t, 5, totalItems)

	ref, err := it.Next()
	require.NoError(t, err)
	require.NotNil(t, ref)
	require.True(t, ref.String() == ref1.String())

	ref, err = it.Next()
	require.NoError(t, err)
	require.NotNil(t, ref)
	require.True(t, ref.String() == ref2.String())

	a, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)

	require.NoError(t, it.Close())
}
