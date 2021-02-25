/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestCriteria(t *testing.T) {
	c := NewCriteria(WithType(vocab.TypeCreate, vocab.TypeAnnounce))
	require.NotNil(t, c)
	require.Len(t, c.Types, 2)
	require.Equal(t, vocab.TypeCreate, c.Types[0])
	require.Equal(t, vocab.TypeAnnounce, c.Types[1])
}
