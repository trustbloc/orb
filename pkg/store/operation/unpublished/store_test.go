/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package unpublished

import (
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/store/expiry"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{
			ErrOpenStore: fmt.Errorf("failed to open store"),
		}, expiry.NewService(time.Millisecond))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.NoError(t, err)
	})

	t.Run("error - store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrPut: fmt.Errorf("error put"),
			ErrGet: storage.ErrDataNotFound,
		}}

		s, err := New(storeProvider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("random get error"),
		}}

		s, err := New(storeProvider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"unable to check for pending operations for suffix[suffix], please re-submit your operation request at later time: random get error") // nolint:lll
	})

	t.Run("error - consecutive put", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"pending operation found for suffix[suffix], please re-submit your operation request at later time")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.NoError(t, err)

		op, err := s.Get("suffix")
		require.NoError(t, err)
		require.Equal(t, op.UniqueSuffix, "suffix")
	})

	t.Run("error - operation without suffix", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save unpublished operation: suffix is empty")
	})

	t.Run("error - from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		op, err := s.Get("suffix")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, op)
	})

	t.Run("error - unmarshal operation", func(t *testing.T) {
		provider := mem.NewProvider()

		store, err := provider.OpenStore(nameSpace)
		require.NoError(t, err)

		err = store.Put("suffix", []byte("not-json"))
		require.NoError(t, err)

		s, err := New(provider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		op, err := s.Get("suffix")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal unpublished operation for suffix[suffix]")
		require.Nil(t, op)
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.NoError(t, err)

		err = s.Delete("suffix")
		require.NoError(t, err)
	})

	t.Run("error - from store delete", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrDelete: fmt.Errorf("delete error"),
		}}

		s, err := New(storeProvider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Delete("suffix")
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete error")
	})
}

func TestStore_DeleteAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix"})
		require.NoError(t, err)

		err = s.DeleteAll([]string{"suffix"})
		require.NoError(t, err)
	})

	t.Run("success - no suffixes provided", func(t *testing.T) {
		s, err := New(mem.NewProvider(), expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.DeleteAll(nil)
		require.NoError(t, err)
	})

	t.Run("error - from store batch", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrBatch: fmt.Errorf("batch error"),
		}}

		s, err := New(storeProvider, expiry.NewService(time.Millisecond))
		require.NoError(t, err)

		err = s.DeleteAll([]string{"suffix"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}
