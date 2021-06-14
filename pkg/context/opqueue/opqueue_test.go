/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	ctxmocks "github.com/trustbloc/orb/pkg/context/mocks"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

//go:generate counterfeiter -o ../mocks/pubsub.gen.go --fake-name PubSub . pubSub

var (
	op1 = &operation.QueuedOperation{UniqueSuffix: "op1"}
	op2 = &operation.QueuedOperation{UniqueSuffix: "op2"}
	op3 = &operation.QueuedOperation{UniqueSuffix: "op3"}
)

func TestQueue(t *testing.T) {
	ps := mempubsub.New(mempubsub.DefaultConfig())

	q, err := New(Config{}, ps)
	require.NoError(t, err)
	require.NotNil(t, q)

	require.Zero(t, q.Len())

	ops, err := q.Peek(2)
	require.NoError(t, err)
	require.Empty(t, ops)

	_, err = q.Add(op1, 100)
	require.NoError(t, err)

	_, err = q.Add(op2, 101)
	require.NoError(t, err)

	_, err = q.Add(op3, 101)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	ops, err = q.Peek(2)
	require.NoError(t, err)
	require.Len(t, ops, 2)
	require.Equal(t, *op1, ops[0].QueuedOperation)
	require.Equal(t, uint64(100), ops[0].ProtocolGenesisTime)
	require.Equal(t, *op2, ops[1].QueuedOperation)
	require.Equal(t, uint64(101), ops[1].ProtocolGenesisTime)

	removed, n, err := q.Remove(2)
	require.NoError(t, err)
	require.Equal(t, uint(1), n)
	require.Equal(t, uint(2), removed)
	require.Equal(t, uint(1), q.Len())

	removed, n, err = q.Remove(2)
	require.NoError(t, err)
	require.Equal(t, uint(0), n)
	require.Equal(t, uint(1), removed)
}

func TestQueue_Error(t *testing.T) {
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

		_, _, err = q.Remove(1)
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
