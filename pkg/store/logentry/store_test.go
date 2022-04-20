/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logentry

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

const logURL = "https://vct.com/log"

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
		require.Contains(t, err.Error(), "failed to open log entry store: open store error")
		require.Nil(t, s)
	})
}

func TestStore_StoreLogEntries(t *testing.T) {
	t.Run("success - one entry", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		entries := []command.LeafEntry{{
			LeafInput: []byte("leafInput"),
		}}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.NoError(t, err)
	})

	t.Run("success - multiple entries", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		entries := []command.LeafEntry{
			{
				LeafInput: []byte("leafInput-0"),
			},
			{
				LeafInput: []byte("leafInput-1"),
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)
	})

	t.Run("error - no entries", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.StoreLogEntries(logURL, 0, 0, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing log entries")
	})

	t.Run("error - no entries", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		entries := []command.LeafEntry{{
			LeafInput: []byte("leafInput"),
		}}

		err = s.StoreLogEntries("", 0, 0, entries)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing log URL")
	})

	t.Run("success - entries count mismatch", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		entries := []command.LeafEntry{
			{
				LeafInput: []byte("leafInput-0"),
			},
			{
				LeafInput: []byte("leafInput-1"),
			},
		}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting 1 log entries, got 2 entries")
	})

	t.Run("error - store error", func(t *testing.T) {
		store := &mocks.Store{}
		store.BatchReturns(fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		entries := []command.LeafEntry{{
			LeafInput: []byte("leafInput"),
		}}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}
