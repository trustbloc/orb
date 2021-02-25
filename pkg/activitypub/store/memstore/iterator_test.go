/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestIterator(t *testing.T) {
	const (
		activityID1 = "activity1"
		activityID2 = "activity2"
	)

	activity1 := vocab.NewAnnounceActivity(activityID1, vocab.NewObjectProperty())
	activity2 := vocab.NewAnnounceActivity(activityID2, vocab.NewObjectProperty())

	results := []*vocab.ActivityType{activity1, activity2}

	it := newIterator(results)
	require.NotNil(t, it)

	for i := 0; i < 2; i++ {
		a, err := it.Next()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.True(t, a.ID() == activityID1 || a.ID() == activityID2)
	}

	a, err := it.Next()
	require.Error(t, err)
	require.True(t, errors.Is(err, spi.ErrNotFound))
	require.Nil(t, a)

	require.NotPanics(t, it.Close)
}
