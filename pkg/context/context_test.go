/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-svc-go/pkg/batch/opqueue"
)

func TestNew(t *testing.T) {
	c := New(nil, nil, &opqueue.MemQueue{})
	require.NotNil(t, c)

	require.Equal(t, nil, c.Anchor())
	require.Equal(t, nil, c.Protocol())
	require.NotNil(t, c.OperationQueue())
}
