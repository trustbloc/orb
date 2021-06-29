/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	ctxmocks "github.com/trustbloc/orb/pkg/context/mocks"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/amqp"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

//go:generate counterfeiter -o ../mocks/pubsub.gen.go --fake-name PubSub . pubSub

const (
	dockerImage = "rabbitmq"
	dockerTag   = "3-management-alpine"
	mqURI       = "amqp://guest:guest@localhost:5672/"
)

func TestQueue(t *testing.T) {
	log.SetLevel("sidetree_context", log.DEBUG)
	log.SetLevel("pubsub", log.DEBUG)

	operations := newProcessedOperations(10)

	ps1 := amqp.New(amqp.Config{URI: mqURI})
	require.NotNil(t, ps1)

	defer ps1.Stop()

	ps2 := amqp.New(amqp.Config{URI: mqURI})
	require.NotNil(t, ps2)

	defer ps2.Stop()

	q1, err := New(Config{PoolSize: 8}, ps1)
	require.NoError(t, err)
	require.NotNil(t, q1)

	defer q1.Stop()

	require.Zero(t, q1.Len())

	ops1, err := q1.Peek(2)
	require.NoError(t, err)
	require.Empty(t, ops1)

	q2, err := New(Config{PoolSize: 8}, ps2)
	require.NoError(t, err)
	require.NotNil(t, q2)

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

	time.Sleep(time.Second)

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

	t.Run("Not started error", func(t *testing.T) {
		q, err := New(Config{}, ps)
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
		ps.PublishReturns(errExpected)

		q, err := New(Config{}, ps)
		require.NoError(t, err)
		require.NotNil(t, q)

		_, err = q.Add(op1, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Subscribe error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &ctxmocks.PubSub{}
		ps.SubscribeWithOptsReturns(nil, errExpected)

		_, err := New(Config{}, ps)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Marshal error", func(t *testing.T) {
		q, err := New(Config{}, ps)
		require.NoError(t, err)
		require.NotNil(t, q)

		errExpected := errors.New("injected marshal error")

		q.jsonMarshal = func(i interface{}) ([]byte, error) {
			return nil, errExpected
		}

		_, err = q.Add(op1, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		q, err := New(Config{}, ps)
		require.NoError(t, err)
		require.NotNil(t, q)

		errExpected := errors.New("injected unmarshal error")

		q.jsonUnmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		_, err = q.Add(op1, 100)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		_, err = q.Peek(2)
		require.NoError(t, err)
		require.Empty(t, q.pending)
	})
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	resource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerImage,
		Tag:        dockerTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5672/tcp": {{HostIP: "", HostPort: "5672"}},
		},
	})
	if err != nil {
		logger.Errorf(`Failed to start RabbitMQ Docker image.`)

		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(resource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

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
		pOp := po[op.UniqueSuffix]
		require.False(t, pOp.processed)
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
