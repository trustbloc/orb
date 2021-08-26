/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcstatus

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

const vcID = "vcID"

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - open store fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, fmt.Errorf("open store error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open vc-status store: open store error")
		require.Nil(t, s)
	})

	t.Run("error - set store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to set store configuration: set store config error")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.NoError(t, err)
	})

	t.Run("error - marshal error", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.PutReturns(fmt.Errorf("put error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success - in process", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.NoError(t, err)
		require.Equal(t, proof.VCStatusInProcess, status)
	})

	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.VCStatusCompleted)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.NoError(t, err)
		require.Equal(t, proof.VCStatusCompleted, status)
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func([]byte, interface{}) error {
			return errExpected
		}

		err = s.AddStatus(vcID, proof.VCStatusInProcess)
		require.NoError(t, err)

		_, err = s.GetStatus(vcID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("get error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("error - iterator next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator value() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(nil, fmt.Errorf("iterator value() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.Contains(t, err.Error(), "iterator value() error")
	})
}
