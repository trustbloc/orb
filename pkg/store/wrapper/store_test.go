/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	s := NewStore(&ariesmockstorage.Store{}, "CouchDB")
	require.NotNil(t, s)

	t.Run("put", func(t *testing.T) {
		require.NoError(t, s.Put("k1", []byte("v1")))
	})

	t.Run("get", func(t *testing.T) {
		_, err := s.Get("k2")
		require.NoError(t, err)
	})

	t.Run("get tags", func(t *testing.T) {
		_, err := s.GetTags("k2")
		require.NoError(t, err)
	})

	t.Run("get tags", func(t *testing.T) {
		_, err := s.GetBulk("k2")
		require.NoError(t, err)
	})

	t.Run("query", func(t *testing.T) {
		_, err := s.Query("q1")
		require.NoError(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		require.NoError(t, s.Delete("k3"))
	})

	t.Run("batch", func(t *testing.T) {
		require.NoError(t, s.Batch(nil))
	})

	t.Run("flush", func(t *testing.T) {
		require.NoError(t, s.Flush())
	})

	t.Run("close", func(t *testing.T) {
		require.NoError(t, s.Close())
	})
}
