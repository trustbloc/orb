/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package multierror

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestError(t *testing.T) {
	var err0 *Error
	require.Empty(t, err0.Errors())

	err1 := New()
	require.NotNil(t, err1)
	require.Empty(t, err1.Error())

	err1.Set("1111", errors.New("injected error1"))
	err1.Set("2222", errors.New("injected error2"))

	err := fmt.Errorf("got some error with cause: %w", err1)

	var mErr *Error
	require.True(t, errors.As(err, &mErr))
	require.NotNil(t, mErr)
	require.Len(t, mErr.Errors(), 2)
}
