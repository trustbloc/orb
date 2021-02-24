/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	c := New(nil, nil)
	require.NotNil(t, c)

	require.Equal(t, nil, c.Anchor())
	require.Equal(t, nil, c.Protocol())
	require.NotNil(t, c.OperationQueue())
}
