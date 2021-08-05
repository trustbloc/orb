/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
)

var logger = log.New("sidetree_context")

const topic = "opqueue"

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

type operationMessage struct {
	msg       *message.Message
	op        *operation.QueuedOperationAtTime
	timeAdded time.Time
}

type metricsProvider interface {
	AddOperationTime(value time.Duration)
	BatchCutTime(value time.Duration)
	BatchRollbackTime(value time.Duration)
	BatchAckTime(value time.Duration)
	BatchNackTime(value time.Duration)
	BatchSize(value float64)
}

// Config contains configuration parameters for the operation queue.
type Config struct {
	PoolSize uint
}

// Queue implements an operation queue that uses a publisher/subscriber.
type Queue struct {
	*lifecycle.Lifecycle

	pubSub        pubSub
	msgChan       <-chan *message.Message
	mutex         sync.RWMutex
	pending       []*operationMessage
	jsonMarshal   func(interface{}) ([]byte, error)
	jsonUnmarshal func(data []byte, v interface{}) error
	metrics       metricsProvider
}

// New returns a new operation queue.
func New(cfg Config, pubSub pubSub, metrics metricsProvider) (*Queue, error) {
	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), topic, spi.WithPool(cfg.PoolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	q := &Queue{
		pubSub:        pubSub,
		msgChan:       msgChan,
		jsonMarshal:   json.Marshal,
		jsonUnmarshal: json.Unmarshal,
		metrics:       metrics,
	}

	q.Lifecycle = lifecycle.New("operation-queue",
		lifecycle.WithStart(q.start),
		lifecycle.WithStop(q.stop),
	)

	q.Start()

	return q, nil
}

// Add publishes the given operation.
func (q *Queue) Add(op *operation.QueuedOperation, protocolGenesisTime uint64) (uint, error) {
	if q.State() != lifecycle.StateStarted {
		return 0, lifecycle.ErrNotStarted
	}

	startTime := time.Now()

	defer func() {
		q.metrics.AddOperationTime(time.Since(startTime))
	}()

	b, err := q.jsonMarshal(
		&operation.QueuedOperationAtTime{
			QueuedOperation:     *op,
			ProtocolGenesisTime: protocolGenesisTime,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("marshall queued operation: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), b)

	logger.Debugf("Publishing operation message to topic [%s] - Msg [%s], DID [%s]", topic, msg.UUID, op.UniqueSuffix)

	err = q.pubSub.Publish(topic, msg)
	if err != nil {
		return 0, fmt.Errorf("publish queued operation: %w", err)
	}

	q.mutex.RLock()
	defer q.mutex.RUnlock()

	// Return the current pending operations which does not include the new operation (since it hasn't
	// been processed yet). This is OK since the resulting value isn't currently used.
	return uint(len(q.pending)), nil
}

// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
func (q *Queue) Peek(num uint) (operation.QueuedOperationsAtTime, error) {
	if q.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	q.mutex.RLock()
	defer q.mutex.RUnlock()

	n := int(num)
	if len(q.pending) < n {
		n = len(q.pending)
	}

	return asQueuedOperations(q.pending[0:n]), nil
}

// Remove removes (up to) the given number of items from the head of the queue.
// Returns the actual number of items that were removed and the new length of the queue.
// Each removed message is acknowledged, indicating that it was successfully processed. If the
// server goes down with messages still in the queue then, if using a durable message queue, the messages
// will be delivered to another server instance which is processing from the same queue.
func (q *Queue) Remove(num uint) (ops operation.QueuedOperationsAtTime, ack func() uint, nack func(), err error) {
	if q.State() != lifecycle.StateStarted {
		return nil, nil, nil, lifecycle.ErrNotStarted
	}

	startTime := time.Now()

	q.mutex.Lock()
	defer q.mutex.Unlock()

	n := int(num)
	if len(q.pending) < n {
		n = len(q.pending)
	}

	if n == 0 {
		return nil,
			func() uint { return 0 },
			func() {}, nil
	}

	items := q.pending[0:n]
	q.pending = q.pending[n:]

	return asQueuedOperations(items), q.newAckFunc(items, startTime), q.newNackFunc(items, startTime), nil
}

// Len returns the length of the pending queue.
func (q *Queue) Len() uint {
	if q.State() != lifecycle.StateStarted {
		return 0
	}

	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return uint(len(q.pending))
}

func (q *Queue) start() {
	go q.listen()

	logger.Infof("Started operation queue")
}

func (q *Queue) stop() {
	q.mutex.RLock()

	logger.Debugf("Stopping operation queue with %d pending operations...", len(q.pending))

	items := make([]*operationMessage, len(q.pending))

	for i, item := range q.pending {
		items[i] = item
	}

	q.mutex.RUnlock()

	logger.Debugf("... nacking %d pending pending...", len(items))

	for _, item := range items {
		logger.Debugf("Nacking item [%s] - [%s]", item.msg.UUID)

		item.msg.Nack()
	}

	logger.Debugf("...stopped operation queue.")
}

func (q *Queue) listen() {
	logger.Debugf("Starting message listener")

	for msg := range q.msgChan {
		q.handleMessage(msg)
	}

	logger.Debugf("Message listener stopped")
}

func (q *Queue) handleMessage(msg *message.Message) {
	logger.Debugf("Handling operation message [%s]", msg.UUID)

	op := &operation.QueuedOperationAtTime{}

	err := q.jsonUnmarshal(msg.Payload, op)
	if err != nil {
		logger.Errorf("Error unmarshalling operation: %s", err)

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	q.mutex.Lock()
	defer q.mutex.Unlock()

	logger.Debugf("Adding operation message to pending queue [%s] - DID [%s]", msg.UUID, op.UniqueSuffix)

	// Add the message to our in-memory queue but don't acknowledge it yet. The message
	// will be acknowledged when Remove() is called.
	q.pending = append(q.pending, &operationMessage{
		msg:       msg,
		op:        op,
		timeAdded: time.Now(),
	})
}

func (q *Queue) newAckFunc(items []*operationMessage, startTime time.Time) func() uint {
	return func() uint {
		logger.Infof("Acking %d operation messages...", len(items))

		// Acknowledge all of the messages that were processed.
		for _, opMsg := range items {
			opMsg.msg.Ack()

			logger.Infof("Acknowledged message [%s] - DID [%s]", opMsg.msg.UUID, opMsg.op.UniqueSuffix)
		}

		// Batch cut time is the time since the first operation was added (which is the oldest operation in the batch).
		q.metrics.BatchCutTime(time.Since(items[0].timeAdded))

		// Batch Ack time is the time it took to acknowledge all of the MQ messages.
		q.metrics.BatchAckTime(time.Since(startTime))

		q.metrics.BatchSize(float64(len(items)))

		q.mutex.RLock()
		defer q.mutex.RUnlock()

		return uint(len(q.pending))
	}
}

func (q *Queue) newNackFunc(items []*operationMessage, startTime time.Time) func() {
	return func() {
		logger.Infof("Nacking %d operation messages...", len(items))

		// Send an Nack for all of the messages that were removed so that they may be retried.
		for _, opMsg := range items {
			opMsg.msg.Nack()

			logger.Infof("Nacked message [%s] - DID [%s]", opMsg.msg.UUID, opMsg.op.UniqueSuffix)
		}

		// Batch rollback time is the time since the first operation was added (which is the oldest operation in the batch).
		q.metrics.BatchRollbackTime(time.Since(items[0].timeAdded))

		// Batch Ack time is the time it took to nack all of the MQ messages.
		q.metrics.BatchNackTime(time.Since(startTime))
	}
}

func asQueuedOperations(opMsgs []*operationMessage) []*operation.QueuedOperationAtTime {
	ops := make([]*operation.QueuedOperationAtTime, len(opMsgs))

	logger.Debugf("Returning %d queued operations:", len(opMsgs))

	for i, opMsg := range opMsgs {
		logger.Debugf("- Msg [%s], DID [%s]", opMsg.msg.UUID, opMsg.op.UniqueSuffix)

		ops[i] = opMsg.op
	}

	return ops
}
