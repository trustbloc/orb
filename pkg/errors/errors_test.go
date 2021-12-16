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

	err = NewTransientf("some transient error")
	require.True(t, IsTransient(err))
}

func TestBadRequestError(t *testing.T) {
	eir := errors.New("some bad request error")
	e := errors.New("some other error")

	err := fmt.Errorf("got error: %w", NewBadRequest(eir))

	require.True(t, IsBadRequest(err))
	require.True(t, errors.Is(err, eir))
	require.False(t, IsBadRequest(e))
	require.EqualError(t, err, "got error: some bad request error")

	err = NewBadRequestf("some bad request")
	require.True(t, IsBadRequest(err))
}
