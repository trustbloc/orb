/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorstatus

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/encoder"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
	"github.com/trustbloc/orb/pkg/store/expiry"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	vcID = "vcID"

	maxWitnessDelayTime = 30 * time.Second
)

func TestNew(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - open store fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, fmt.Errorf("open store error"))

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open store [anchor-status]: open store error")
		require.Nil(t, s)
	})

	t.Run("error - set store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.Error(t, err)
		require.Contains(t, err.Error(), "set store configuration for [anchor-status]: set store config error")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)
	})

	t.Run("error - marshal error", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.PutReturns(fmt.Errorf("put error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestStore_Get(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success - in process", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.NoError(t, err)
		require.Equal(t, proof.AnchorIndexStatusInProcess, status)
	})

	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.NoError(t, err)
		require.Equal(t, proof.AnchorIndexStatusCompleted, status)
	})

	t.Run("error - unmarshal error", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func([]byte, interface{}) error {
			return errExpected
		}

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		_, err = s.GetStatus(vcID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("error - not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("get error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
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

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
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

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		status, err := s.GetStatus(vcID)
		require.Error(t, err)
		require.Empty(t, status)
		require.Contains(t, err.Error(), "iterator value() error")
	})
}

func TestStore_CheckInProcessAnchors(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success - in process(time not past status check time)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("success - no incomplete records", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		s.checkStatusAfterTimePeriod = time.Second

		time.Sleep(2 * time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("success - in process(time past status check time, one record)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		s.checkStatusAfterTimePeriod = time.Second

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("stopped", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithCheckStatusAfterTime(500*time.Millisecond),
			WithMaxRecordsPerInterval(1),
			WithMonitoringInterval(9*time.Second))
		require.NoError(t, err)

		s.Stop()

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("success - in process(time past status check time, multiple records)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithCheckStatusAfterTime(time.Second),
			WithMaxRecordsPerInterval(1),
			WithMonitoringInterval(9*time.Second))
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.AddStatus("otherVC", proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		require.Equal(t, 3*time.Second, s.CheckInProcessAnchors())
	})

	t.Run("success - completed(time past status check time, previously failed to delete in-process)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithCheckStatusAfterTime(time.Second))
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("error - process in-complete error", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithCheckStatusAfterTime(time.Second), WithPolicyHandler(&mockPolicyHandler{Err: fmt.Errorf("policy error")}))
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("process incomplete - witnesses found", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithCheckStatusAfterTime(time.Second),
			WithPolicyHandler(
				&mockPolicyHandler{
					Err: fmt.Errorf("unable to select additional witnesses: %w", orberrors.ErrWitnessesNotFound),
				},
			),
		)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("error - query error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("query error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("error - iterator next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})

	t.Run("error - iterator second next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.ValueReturns([]byte(`{"status": "in-process"}`), nil)
		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, fmt.Errorf("iterator second next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		require.Equal(t, time.Duration(0), s.CheckInProcessAnchors())
	})
}

func TestStore_deleteInProcessStatus(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
		require.NoError(t, err)
	})

	t.Run("nothing to delete -> success", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
		require.NoError(t, err)
	})

	t.Run("error - query error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("query error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
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

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator key() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.ValueReturns([]byte(`{"status": "in-process"}`), nil)
		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, nil)

		iterator.TagsReturns([]storage.Tag{{Name: statusTagName, Value: string(proof.AnchorIndexStatusInProcess)}}, nil)

		iterator.KeyReturns("", fmt.Errorf("iterator key() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator key() error")
	})

	t.Run("error - iterator second next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.ValueReturns([]byte(`{"status": "in-process"}`), nil)
		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, fmt.Errorf("iterator second next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.deleteInProcessStatus(vcID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator second next() error")
	})
}

func TestStore_processIndex(t *testing.T) {
	taskMgr := testutil.GetTaskMgr(t)

	expiryService := expiry.NewService(taskMgr, time.Second)

	t.Run("success", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.processIndex(encoder.EncodeToString([]byte(vcID)))
		require.NoError(t, err)
	})

	t.Run("error - anchor ID not encoded", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.processIndex("/invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data at input byte 0")
	})

	t.Run("error - policy handler error", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithPolicyHandler(&mockPolicyHandler{Err: fmt.Errorf("policy error")}))
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.processIndex(encoder.EncodeToString([]byte(vcID)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to re-evaluate policy for anchorID[vcID]: policy error")
	})

	t.Run("ignore - status not found", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime,
			WithPolicyHandler(&mockPolicyHandler{Err: fmt.Errorf("policy error")}))
		require.NoError(t, err)

		err = s.processIndex(encoder.EncodeToString([]byte(vcID)))
		require.NoError(t, err)
	})

	t.Run("ignore - status completed", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := New(mongoDBProvider, taskMgr, expiryService, maxWitnessDelayTime)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusCompleted)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.AddStatus(vcID, proof.AnchorIndexStatusInProcess)
		require.NoError(t, err)

		err = s.processIndex(encoder.EncodeToString([]byte(vcID)))
		require.NoError(t, err)
	})
}

type mockPolicyHandler struct {
	Err error
}

func (m *mockPolicyHandler) CheckPolicy(_ string) error {
	return m.Err
}
