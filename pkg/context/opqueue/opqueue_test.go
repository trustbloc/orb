/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	ctxmocks "github.com/trustbloc/orb/pkg/context/mocks"
	"github.com/trustbloc/orb/pkg/internal/testutil/rabbitmqtestutil"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/amqp"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

//go:generate counterfeiter -o ../mocks/pubsub.gen.go --fake-name PubSub . pubSub
//go:generate counterfeiter -o ../mocks/DataExpiryService.gen.go --fake-name DataExpiryService . dataExpiryService

// mqURI will get set in the TestMain function.
var mqURI = ""

func TestQueue(t *testing.T) {
	log.SetLevel("sidetree_context", log.DEBUG)
	log.SetLevel("pubsub", log.DEBUG)

	storageProvider := storage.NewMockStoreProvider()

	taskMgr1 := servicemocks.NewTaskManager("taskmgr1").WithInterval(500 * time.Millisecond)

	taskMgr1.Start()
	defer taskMgr1.Stop()

	taskMgr2 := servicemocks.NewTaskManager("taskmgr2").WithInterval(500 * time.Millisecond)

	taskMgr2.Start()
	defer taskMgr2.Stop()

	operations := newProcessedOperations(10)

	ps1 := amqp.New(amqp.Config{URI: mqURI})
	require.NotNil(t, ps1)

	defer ps1.Stop()

	ps2 := amqp.New(amqp.Config{URI: mqURI})
	require.NotNil(t, ps2)

	defer ps2.Stop()

	q1, err := New(
		Config{
			PoolSize:            8,
			TaskMonitorInterval: time.Second,
			MaxRetries:          1,
			RetriesInitialDelay: 10 * time.Millisecond,
			RetriesMaxDelay:     10 * time.Millisecond,
			RetriesMultiplier:   1.0,
		},
		ps1, storageProvider, taskMgr1, &ctxmocks.DataExpiryService{},
		&mocks.MetricsProvider{},
	)
	require.NoError(t, err)
	require.NotNil(t, q1)

	q1.Start()
	defer q1.Stop()

	require.Zero(t, q1.Len())

	ops1, err := q1.Peek(2)
	require.NoError(t, err)
	require.Empty(t, ops1)

	q2, err := New(
		Config{
			PoolSize:            8,
			TaskMonitorInterval: time.Second,
			MaxRetries:          1,
			RetriesInitialDelay: 10 * time.Millisecond,
			RetriesMaxDelay:     10 * time.Millisecond,
			RetriesMultiplier:   1.0,
		},

		ps2, storageProvider, taskMgr2, &ctxmocks.DataExpiryService{},
		&mocks.MetricsProvider{},
	)
	require.NoError(t, err)
	require.NotNil(t, q2)

	q2.Start()
	defer q2.Stop()

	require.Zero(t, q2.Len())

	ops2, err := q2.Peek(2)
	require.NoError(t, err)
	require.Empty(t, ops2)

	removedOps1, ack1, nack1, err := q1.Remove(2)
	require.NoError(t, err)
	require.Empty(t, removedOps1)
	require.Equal(t, uint(0), ack1())
	require.NotPanics(t, nack1)

	for _, op := range operations {
		_, err = q1.Add(op.op, 100)
		require.NoError(t, err)
	}

	time.Sleep(100 * time.Millisecond)

	ops1, err = q1.Peek(10)
	require.NoError(t, err)
	require.NotEmpty(t, ops1)

	ops2, err = q2.Peek(10)
	require.NoError(t, err)
	require.NotEmpty(t, ops2)

	removedOps1, ack1, _, err = q1.Remove(2)
	require.NoError(t, err)

	pending := ack1()
	require.True(t, pending > 0)
	require.True(t, q1.Len() > 0)
	require.Len(t, removedOps1, 2)

	operations.setProcessed(t, removedOps1)

	removedOps1, _, nack1, err = q1.Remove(2)
	require.NoError(t, err)
	require.Len(t, removedOps1, 2)

	nack1()

	time.Sleep(100 * time.Millisecond)

	removedOps1, ack1, _, err = q1.Remove(1)
	require.NoError(t, err)

	ack1()

	operations.setProcessed(t, removedOps1)

	time.Sleep(100 * time.Millisecond)

	// Stop the pub/sub for q1. All messages should be diverted to q2.
	q1.Stop()
	ps1.Stop()
	taskMgr1.Stop()

	time.Sleep(5 * time.Second)

	removedOps2, ack2, _, err := q2.Remove(10)
	require.NoError(t, err)

	pending = ack2()
	require.Equal(t, uint(0), pending)
	require.Equal(t, uint(0), q2.Len())

	operations.setProcessed(t, removedOps2)

	removedOps2, _, _, err = q2.Remove(10)
	require.NoError(t, err)
	require.Empty(t, removedOps2)

	var notProcessed []*processedOperation

	for _, op := range operations {
		if !op.processed {
			t.Logf("Not processed: %s", op.op.UniqueSuffix)

			notProcessed = append(notProcessed, op)
		}
	}

	require.Emptyf(t, notProcessed, "%d operations were not processed", len(notProcessed))
}

func TestQueue_Error(t *testing.T) {
	op1 := &operation.QueuedOperation{UniqueSuffix: "op1"}

	ps := mempubsub.New(mempubsub.DefaultConfig())
	defer ps.Stop()

	taskMgr := servicemocks.NewTaskManager("taskmgr1")

	t.Run("Not started error", func(t *testing.T) {
		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Stop()

		_, err = q.Add(op1, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), lifecycle.ErrNotStarted.Error())

		_, err = q.Peek(1)
		require.Error(t, err)
		require.Contains(t, err.Error(), lifecycle.ErrNotStarted.Error())

		_, _, _, err = q.Remove(1)
		require.Error(t, err)
		require.Contains(t, err.Error(), lifecycle.ErrNotStarted.Error())

		require.Equal(t, uint(0), q.Len())
	})

	t.Run("Publish error", func(t *testing.T) {
		errExpected := errors.New("injected publish error")

		ps := &ctxmocks.PubSub{}
		ps.PublishWithOptsReturns(errExpected)

		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		_, err = q.Add(op1, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Subscribe error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &ctxmocks.PubSub{}
		ps.SubscribeWithOptsReturns(nil, errExpected)

		_, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Marshal error", func(t *testing.T) {
		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		errExpected := errors.New("injected marshal error")

		q.marshal = func(i interface{}) ([]byte, error) {
			return nil, errExpected
		}

		_, err = q.Add(op1, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		errExpected := errors.New("injected unmarshal error")

		q.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		_, err = q.Add(op1, 100)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		_, err = q.Peek(2)
		require.NoError(t, err)
		require.Empty(t, q.pending)
	})

	t.Run("UpdateTaskTime error", func(t *testing.T) {
		p := storage.NewMockStoreProvider()

		s, err := p.OpenStore(storeName)
		require.NoError(t, err)

		errExpected := errors.New("injected put error")

		s.(*storage.MockStore).ErrPut = errExpected //nolint:forcetypeassert

		q, err := New(Config{}, ps, p,
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, q)
	})

	t.Run("Query DB error", func(t *testing.T) {
		mgr := servicemocks.NewTaskManager("taskmgr1").WithInterval(100 * time.Millisecond)

		mgr.Start()
		defer mgr.Stop()

		p := storage.NewMockStoreProvider()

		s, err := p.OpenStore(storeName)
		require.NoError(t, err)

		errExpected := errors.New("injected query error")

		s.(*storage.MockStore).ErrQuery = errExpected //nolint:forcetypeassert

		q, err := New(Config{}, ps, p,
			mgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		time.Sleep(time.Second)
	})

	t.Run("NextTask iterator error", func(t *testing.T) {
		mgr := servicemocks.NewTaskManager("taskmgr1").WithInterval(100 * time.Millisecond)

		mgr.Start()
		defer mgr.Stop()

		p := storage.NewMockStoreProvider()

		s, err := p.OpenStore(storeName)
		require.NoError(t, err)

		errExpected := errors.New("injected iterator next error")

		s.(*storage.MockStore).ErrNext = errExpected //nolint:forcetypeassert

		q, err := New(Config{}, ps, p,
			mgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		time.Sleep(time.Second)
	})

	t.Run("NextTask unmarshal error", func(t *testing.T) {
		mgr := servicemocks.NewTaskManager("taskmgr1").WithInterval(100 * time.Millisecond)

		mgr.Start()
		defer mgr.Stop()

		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			mgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		errExpected := errors.New("injected unmarshal next error")

		q.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		q.Start()
		defer q.Stop()

		time.Sleep(time.Second)
	})

	t.Run("Re-post publish error", func(t *testing.T) {
		errExpected := errors.New("injected publish error")

		ps := &ctxmocks.PubSub{}
		ps.PublishWithOptsReturnsOnCall(0, errExpected)

		q, err := New(Config{}, ps, storage.NewMockStoreProvider(),
			taskMgr, &ctxmocks.DataExpiryService{}, &mocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, q)

		q.Start()
		defer q.Stop()

		op := &operation.QueuedOperation{
			OperationRequest: []byte("request"),
			UniqueSuffix:     "suffix1",
			Namespace:        "ns1",
		}

		opMsg := &OperationMessage{
			ID: uuid.New().String(),
			Operation: &operation.QueuedOperationAtTime{
				QueuedOperation: *op,
				ProtocolVersion: 1,
			},
		}

		opBytes, err := json.Marshal(opMsg)
		require.NoError(t, err)

		msg := message.NewMessage(uuid.New().String(), opBytes)

		q.handleMessage(msg)

		time.Sleep(100 * time.Millisecond)

		ops, _, nack, err := q.Remove(1)
		require.NoError(t, err)
		require.Len(t, ops, 1)

		nack()

		ops, _, _, err = q.Remove(1)
		require.NoError(t, err)
		require.Empty(t, ops)
	})
}

func TestRepostWithMaxRetries(t *testing.T) {
	log.SetLevel("sidetree_context", log.DEBUG)
	log.SetLevel("pubsub", log.DEBUG)

	storageProvider := storage.NewMockStoreProvider()

	taskMgr := servicemocks.NewTaskManager("taskmgr1").WithInterval(500 * time.Millisecond)

	taskMgr.Start()
	defer taskMgr.Stop()

	operations := newProcessedOperations(5)

	ps := amqp.New(amqp.Config{URI: mqURI})
	require.NotNil(t, ps)

	defer ps.Stop()

	q, err := New(
		Config{
			PoolSize:            8,
			TaskMonitorInterval: time.Second,
			MaxRetries:          1,
			RetriesInitialDelay: 50 * time.Millisecond,
			RetriesMaxDelay:     100 * time.Millisecond,
			RetriesMultiplier:   1.0,
		},
		ps, storageProvider, taskMgr, &ctxmocks.DataExpiryService{},
		&mocks.MetricsProvider{},
	)
	require.NoError(t, err)
	require.NotNil(t, q)

	q.Start()
	defer q.Stop()

	for _, op := range operations {
		_, err = q.Add(op.op, 100)
		require.NoError(t, err)
	}

	time.Sleep(500 * time.Millisecond)

	removedOps, _, nack, err := q.Remove(5)
	require.NoError(t, err)
	require.Len(t, removedOps, 5)

	nack()

	time.Sleep(time.Second)

	removedOps, _, nack, err = q.Remove(5)
	require.NoError(t, err)
	require.Len(t, removedOps, 5)

	nack()

	removedOps, _, _, err = q.Remove(5)
	require.NoError(t, err)
	require.Emptyf(t, removedOps, "no operations should have been remaining since the max retry count was reached")
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	mqURIDocker, stopRabbitMQ := rabbitmqtestutil.StartRabbitMQ()
	defer stopRabbitMQ()

	mqURI = mqURIDocker

	code = m.Run()
}

type processedOperation struct {
	op        *operation.QueuedOperation
	processed bool
}

type processedOperations map[string]*processedOperation

func (po processedOperations) setProcessed(t *testing.T, ops operation.QueuedOperationsAtTime) {
	t.Helper()

	for _, op := range ops {
		pOp, ok := po[op.UniqueSuffix]

		require.Truef(t, ok, "operation for suffix [%s] not found in processed operations queue", op.UniqueSuffix)
		require.Falsef(t, pOp.processed, "Operation is already processed [%s]", op.UniqueSuffix)

		t.Logf("Setting operation to processed state [%s]", op.UniqueSuffix)

		pOp.processed = true
	}
}

func newProcessedOperations(n int) processedOperations {
	ops := make(processedOperations, n)

	for i := 0; i < n; i++ {
		op := &operation.QueuedOperation{UniqueSuffix: fmt.Sprintf("op%d", i)}

		ops[op.UniqueSuffix] = &processedOperation{op: op}
	}

	return ops
}
