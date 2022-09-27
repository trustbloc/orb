/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestCriteria(t *testing.T) {
	c := NewCriteria(
		WithType(vocab.TypeCreate, vocab.TypeAnnounce),
		WithReferenceType(Inbox),
		WithReferenceIRI(testutil.MustParseURL("https://example.com/ref")),
		WithObjectIRI(testutil.MustParseURL("https://example.com/obj")),
		WithActivityIRIs(
			testutil.MustParseURL("https://example.com/activity1"),
			testutil.MustParseURL("https://example.com/activity2"),
		),
	)
	require.NotNil(t, c)
	require.Len(t, c.Types, 2)
	require.Equal(t, vocab.TypeCreate, c.Types[0])
	require.Equal(t, vocab.TypeAnnounce, c.Types[1])

	b, err := json.Marshal(c)
	require.NoError(t, err)

	t.Logf("%s", b)
}
