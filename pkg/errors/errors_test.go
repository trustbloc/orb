/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransientError(t *testing.T) {
	et := errors.New("some transient error")
	ep := errors.New("some persistent error")

	err := fmt.Errorf("got error: %w", NewTransient(et))

	require.True(t, IsTransient(err))
	require.True(t, errors.Is(err, et))
	require.False(t, IsTransient(ep))
	require.EqualError(t, err, "got error: some transient error")
}
