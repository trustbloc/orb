/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
)

const testLog = "http://vct.com/log"

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{
			ErrOpenStore: fmt.Errorf("failed to open store"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Activate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, testLog, rec.Log)
		require.Equal(t, true, rec.Active)
		require.Nil(t, rec.STH)
	})

	t.Run("success - activate, deactivate, activate", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, true, rec.Active)

		err = s.Deactivate(testLog)
		require.NoError(t, err)

		rec, err = s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, false, rec.Active)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err = s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, true, rec.Active)
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to activate log monitor: log URL is empty")
	})

	t.Run("error - error from store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			GetReturn: []byte("{}"),
			ErrPut:    fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - error from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
	})

	t.Run("error - error from store put", func(t *testing.T) {
		recBytes, err := json.Marshal(&LogMonitor{Log: testLog})
		require.NoError(t, err)

		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			GetReturn: recBytes,
			ErrPut:    fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Deactivate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})
}

func TestStore_Deactivate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, true, rec.Active)

		err = s.Deactivate(testLog)
		require.NoError(t, err)

		rec, err = s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, false, rec.Active)
	})

	t.Run("error - empty log URL", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Deactivate("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deactivate log monitor: log URL is empty")
	})

	t.Run("error - from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Deactivate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
	})

	t.Run("error - marshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.Deactivate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - error from store put", func(t *testing.T) {
		recBytes, err := json.Marshal(&LogMonitor{Log: testLog})
		require.NoError(t, err)

		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			GetReturn: recBytes,
			ErrPut:    fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, rec.Active, true)
		require.Nil(t, rec.STH)
	})

	t.Run("error - from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		vc, err := s.Get(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("error - ErrDataNotFound from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: storage.ErrDataNotFound,
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		vc, err := s.Get(testLog)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, vc)
	})

	t.Run("error - marshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.Activate(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, rec)
	})
}

func TestStore_Update(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.Equal(t, true, rec.Active)
		require.Nil(t, rec.STH)

		rec.Active = false

		err = s.Update(rec)
		require.NoError(t, err)
		require.Equal(t, false, rec.Active)
		require.Nil(t, rec.STH)
	})

	t.Run("error - marshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rec := &LogMonitor{Log: testLog, Active: true}

		err = s.Update(rec)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - error from store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrPut: fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		rec := &LogMonitor{Log: testLog, Active: true}

		err = s.Update(rec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("error - log is nil", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Update(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "log monitor is empty")
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		rec, err := s.Get(testLog)
		require.NoError(t, err)
		require.NotNil(t, rec)

		err = s.Delete(testLog)
		require.NoError(t, err)

		rec, err = s.Get(testLog)
		require.Error(t, err)
		require.Equal(t, err.Error(), "content not found")
		require.Nil(t, rec)
	})

	t.Run("test error from store delete", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrDelete: fmt.Errorf("error delete"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Delete(testLog)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error delete")
	})
}

func TestStore_GetActiveLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		logs, err := s.GetActiveLogs()
		require.NoError(t, err)
		require.NotEmpty(t, logs)
	})
	t.Run("error - query error", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		err = s.Activate(testLog)
		require.NoError(t, err)

		stopMongo()

		logs, err := s.GetActiveLogs()
		require.Error(t, err)
		require.Nil(t, logs)
	})
	t.Run("error - no active logs", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		logs, err := s.GetActiveLogs()
		require.Error(t, err)
		require.Nil(t, logs)
		require.Equal(t, err.Error(), orberrors.ErrContentNotFound.Error())
	})

	t.Run("error - unmarshall error", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider)
		require.NoError(t, err)

		store, err := mongoDBProvider.OpenStore(namespace)
		require.NoError(t, err)

		indexTag := storage.Tag{
			Name:  activeIndex,
			Value: "true",
		}

		err = store.Put(testLog, []byte("not-json"), indexTag)
		require.NoError(t, err)

		logs, err := s.GetActiveLogs()
		require.Error(t, err)
		require.Nil(t, logs)
		require.Contains(t, err.Error(), "unmarshal log monitor: invalid character")
	})
}
