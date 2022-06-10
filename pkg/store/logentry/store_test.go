/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logentry

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
	"github.com/trustbloc/orb/pkg/store/mocks"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring/verifier"
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
		require.Contains(t, err.Error(), "open store error")
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

func TestStore_GetLogEntries(t *testing.T) {
	t.Run("success - one entry", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		testLeafInput := []byte("leafInput")

		entries := []command.LeafEntry{{
			LeafInput: testLeafInput,
		}}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.NoError(t, err)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		entry, err := iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(testLeafInput, entry.LeafInput))

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("success - multiple entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		entry, err := iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(test0, entry.LeafInput))

		entry, err = iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(test1, entry.LeafInput))
	})

	t.Run("error - no entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 0, n)

		entry, err := iter.Next()
		require.Error(t, err)
		require.Nil(t, entry)
		require.Contains(t, err.Error(), "data not found")
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		iter, err := s.GetLogEntries("")
		require.Error(t, err)
		require.Nil(t, iter)
		require.Contains(t, err.Error(), "missing log URL")
	})
}

func TestStore_GetLogEntriesFrom(t *testing.T) {
	t.Run("success - one entry", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		testLeafInput := []byte("leafInput")

		entries := []command.LeafEntry{{
			LeafInput: testLeafInput,
		}}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.NoError(t, err)

		iter, err := s.GetLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		entry, err := iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(testLeafInput, entry.LeafInput))

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("success - multiple entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err := s.GetLogEntriesFrom(logURL, 1)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		entry, err := iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(test1, entry.LeafInput))

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("error - no entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		iter, err := s.GetLogEntriesFrom(logURL, 1)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 0, n)

		entry, err := iter.Next()
		require.Error(t, err)
		require.Nil(t, entry)
		require.Contains(t, err.Error(), "data not found")

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		iter, err := s.GetLogEntriesFrom("", 0)
		require.Error(t, err)
		require.Nil(t, iter)
		require.Contains(t, err.Error(), "missing log URL")
	})
}

func TestStore_FailLogEntriesFrom(t *testing.T) {
	t.Run("success - one entry", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		testLeafInput := []byte("leafInput")

		entries := []command.LeafEntry{{
			LeafInput: testLeafInput,
		}}

		err = s.StoreLogEntries(logURL, 0, 0, entries)
		require.NoError(t, err)

		iter, err := s.GetLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		err = iter.Close()
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err = s.GetLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 0, n)

		err = iter.Close()
		require.NoError(t, err)

		iter, err = s.GetFailedLogEntries(logURL)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("success - multiple entries(split)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		err = s.FailLogEntriesFrom(logURL, 1)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err = s.GetLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		err = iter.Close()
		require.NoError(t, err)

		iter, err = s.GetFailedLogEntries(logURL)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 1, n)

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("success - multiple entries (all)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err = s.GetFailedLogEntries(logURL)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		err = iter.Close()
		require.NoError(t, err)

		iter, err = s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err = iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 0, n)

		err = iter.Close()
		require.NoError(t, err)
	})

	t.Run("success - no entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 1)
		require.NoError(t, err)
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom("", 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing log URL")
	})

	t.Run("error - query error", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("query error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query error")
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

		err = s.FailLogEntriesFrom(logURL, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator tags() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, nil)

		iterator.TagsReturns(nil, fmt.Errorf("iterator tags() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator tags() error")
	})

	t.Run("error - iterator key() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, nil)

		iterator.TagsReturns([]storage.Tag{{Name: statusTagName, Value: string(EntryStatusSuccess)}}, nil)

		iterator.KeyReturns("", fmt.Errorf("iterator key() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator key() error")
	})

	t.Run("error - iterator second next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, fmt.Errorf("iterator second next() error"))
		iterator.ValueReturns([]byte(`{}`), nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator second next() error")
	})
}

func TestStore_GetFailedLogEntries(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		err = s.FailLogEntriesFrom(logURL, 0)
		require.NoError(t, err)

		iter, err := s.GetFailedLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		entry, err := iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(test0, entry.LeafInput))

		entry, err = iter.Next()
		require.NoError(t, err)
		require.True(t, bytes.Equal(test1, entry.LeafInput))
	})

	t.Run("error - no entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		iter, err := s.GetFailedLogEntries(logURL)
		require.NoError(t, err)
		require.NotNil(t, iter)

		entry, err := iter.Next()
		require.Error(t, err)
		require.Nil(t, entry)
		require.Contains(t, err.Error(), "data not found")
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider)
		require.NoError(t, err)

		entries, err := s.GetFailedLogEntries("")
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "missing log URL")
	})
}

func TestEntryIterator(t *testing.T) {
	t.Run("error - next fails", func(t *testing.T) {
		iterator := entryIterator{ariesIterator: &mock.Iterator{ErrNext: fmt.Errorf("next error")}}

		entry, err := iterator.Next()
		require.EqualError(t, err, "failed to determine if there are more results: next error")
		require.Nil(t, entry)

		iterator = entryIterator{ariesIterator: &mock.Iterator{
			NextReturn: true, ErrValue: fmt.Errorf("value error"),
		}}

		entry, err = iterator.Next()
		require.EqualError(t, err, "failed to get value: value error")
		require.Nil(t, entry)
	})
}

func TestGetRootHashFromEntries(t *testing.T) {
	t.Run("success - calculate root hash from retrieved multiple entries", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		test0 := []byte("leafInput-0")
		test1 := []byte("leafInput-1")

		entries := []command.LeafEntry{
			{
				LeafInput: test0,
			},
			{
				LeafInput: test1,
			},
		}

		err = s.StoreLogEntries(logURL, 0, 1, entries)
		require.NoError(t, err)

		time.Sleep(time.Second)

		iter, err := s.GetLogEntries(logURL)
		require.NoError(t, err)

		n, err := iter.TotalItems()
		require.NoError(t, err)
		require.Equal(t, 2, n)

		var retrievedEntries []*command.LeafEntry

		for i := 0; i < n; i++ {
			val, e := iter.Next()
			require.NoError(t, e)

			retrievedEntries = append(retrievedEntries, val)
		}

		v := verifier.New()

		sth, err := v.GetRootHashFromEntries(retrievedEntries)
		require.NoError(t, err)
		require.NotNil(t, sth)
	})
}
