/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ariesstore

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
)

func TestIterators_FailureCases(t *testing.T) {
	t.Run("Reference iterator", func(t *testing.T) {
		iterator := referenceIterator{ariesIterator: &mock.Iterator{ErrNext: errors.New("next error")}}

		activity, err := iterator.Next()
		require.EqualError(t, err, "failed to determine if there are more results: next error")
		require.Nil(t, activity)

		iterator = referenceIterator{ariesIterator: &mock.Iterator{
			NextReturn: true, ErrValue: errors.New("value error"),
		}}

		activity, err = iterator.Next()
		require.EqualError(t, err, "failed to get value: value error")
		require.Nil(t, activity)
	})
}
