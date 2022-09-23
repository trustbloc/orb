/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/store"
)

var logger = log.New("sidetree_context")

const (
	topic            = "orb.operation"
	taskID           = "op-queue-monitor"
	storeName        = "operation-queue"
	tagOpQueueTask   = "taskID"
	tagServerID      = "serverID"
	detachedServerID = "detached"

	defaultInterval             = 10 * time.Second
	defaultTaskExpirationFactor = 2
	defaultMaxRetries           = 10
	defaultRetryInitialDelay    = 2 * time.Second
	defaultMaxRetryDelay        = 30 * time.Second
	defaultRetryMultiplier      = 1.5
)

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	PublishWithOpts(topic string, msg *message.Message, opts ...spi.Option) error
	Close() error
}

// OperationMessage contains the data that is sent to the message broker.
type OperationMessage struct {
	ID        string                           `json:"id"`
	Operation *operation.QueuedOperationAtTime `json:"operation"`
	Retries   int                              `json:"retries"`
}

type queuedOperation struct {
	*OperationMessage

	key       string
	timeAdded time.Time
}

type persistedOperation struct {
	*OperationMessage

	ServerID string `json:"serverID"`
}

type metricsProvider interface {
	AddOperationTime(value time.Duration)
	BatchCutTime(value time.Duration)
	BatchRollbackTime(value time.Duration)
	BatchSize(value float64)
}

type taskManager interface {
	InstanceID() string
	RegisterTask(taskID string, interval time.Duration, task func())
}

type opQueueTask struct {
	// TaskID contains the unique ID of the server instance.
	TaskID string `json:"taskID"`
	// UpdatedTime indicates when the status was last updated.
	UpdatedTime int64 `json:"updatedTime"` // This is a Unix timestamp.
}

// Config contains configuration parameters for the operation queue.
type Config struct {
	// PoolSize is the number of AMQP subscribers that are listening for operation messages.
	PoolSize int
	// TaskMonitorInterval is the interval (period) in which operation queue tasks from other server instances
	// are monitored.
	TaskMonitorInterval time.Duration
	// TaskExpiration is the maximum time that an operation queue task can exist in the database before it is
	// considered to have expired. At which point, any other server instance may delete the task and take over
	// processing of all operations associated with the task.
	TaskExpiration time.Duration
	// MaxRetries is the maximum number of retries for a failed operation in a batch.
	MaxRetries int
	// RetriesInitialDelay is the delay for the initial retry attempt.
	RetriesInitialDelay time.Duration
	// RetriesMaxDelay is the maximum delay for a retry attempt.
	RetriesMaxDelay time.Duration
	// RetriesMultiplier is the multiplier for a retry attempt. For example, if set to 1.5 and
	// the previous retry interval was 2s then the next retry interval is set 3s.
	RetriesMultiplier float64
}

// Queue implements an operation queue that uses a publisher/subscriber.
type Queue struct {
	*lifecycle.Lifecycle

	pubSub                    pubSub
	msgChan                   <-chan *message.Message
	mutex                     sync.RWMutex
	pending                   []*queuedOperation
	marshal                   func(interface{}) ([]byte, error)
	unmarshal                 func(data []byte, v interface{}) error
	metrics                   metricsProvider
	serverInstanceID          string
	store                     storage.Store
	taskMonitorInterval       time.Duration
	taskExpiration            time.Duration
	taskMgr                   taskManager
	maxRetries                int
	redeliveryInitialInterval time.Duration
	maxRedeliveryInterval     time.Duration
	redeliveryMultiplier      float64
}

// New returns a new operation queue.
func New(cfg Config, pubSub pubSub, p storage.Provider, taskMgr taskManager, metrics metricsProvider) (*Queue, error) {
	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), topic, spi.WithPool(cfg.PoolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	s, err := store.Open(p, storeName,
		store.NewTagGroup(tagOpQueueTask),
	)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	cfg = resolveConfig(cfg)

	logger.Infof("Creating operation queue - PoolSize: %d, TaskMonitorInterval: %s, TaskExpiration: %s, "+
		"MaxRetries: %d", cfg.PoolSize, cfg.TaskMonitorInterval, cfg.TaskExpiration, cfg.MaxRetries)

	q := &Queue{
		pubSub:                    pubSub,
		msgChan:                   msgChan,
		marshal:                   json.Marshal,
		unmarshal:                 json.Unmarshal,
		metrics:                   metrics,
		serverInstanceID:          taskMgr.InstanceID(),
		store:                     s,
		taskExpiration:            cfg.TaskExpiration,
		taskMonitorInterval:       cfg.TaskMonitorInterval,
		taskMgr:                   taskMgr,
		maxRetries:                cfg.MaxRetries,
		redeliveryInitialInterval: cfg.RetriesInitialDelay,
		redeliveryMultiplier:      cfg.RetriesMultiplier,
		maxRedeliveryInterval:     cfg.RetriesMaxDelay,
	}

	q.Lifecycle = lifecycle.New("operation-queue", lifecycle.WithStart(q.start))

	logger.Infof("[%s] Storing new operation queue task.", q.serverInstanceID)

	err = q.updateTaskTime(q.serverInstanceID)
	if err != nil {
		return nil, fmt.Errorf("update operation queue task time: %w", err)
	}

	err = q.updateTaskTime(detachedServerID)
	if err != nil {
		return nil, fmt.Errorf("update operation queue task time: %w", err)
	}

	return q, nil
}

// Add publishes the given operation.
func (q *Queue) Add(op *operation.QueuedOperation, protocolVersion uint64) (uint, error) {
	return q.publish(
		&OperationMessage{
			ID: uuid.New().String(),
			Operation: &operation.QueuedOperationAtTime{
				QueuedOperation: *op,
				ProtocolVersion: protocolVersion,
			},
		},
	)
}

func (q *Queue) publish(op *OperationMessage) (uint, error) {
	if q.State() != lifecycle.StateStarted {
		return 0, lifecycle.ErrNotStarted
	}

	startTime := time.Now()

	defer func() {
		q.metrics.AddOperationTime(time.Since(startTime))
	}()

	b, err := q.marshal(op)
	if err != nil {
		return 0, fmt.Errorf("marshall queued operation: %w", err)
	}

	msg := message.NewMessage(watermill.NewUUID(), b)

	delay := q.getDeliveryDelay(op.Retries)

	logger.Debugf("Publishing operation message to topic [%s] - Msg [%s], OpID [%s], DID [%s], "+
		"Retries [%d], Delivery delay [%s]", topic, msg.UUID, op.ID, op.Operation.UniqueSuffix, op.Retries, delay)

	err = q.pubSub.PublishWithOpts(topic, msg, spi.WithDeliveryDelay(delay))
	if err != nil {
		return 0, fmt.Errorf("publish queued operation [%s]: %w", op.ID, err)
	}

	return 0, nil
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

	items := q.pending[0:n]

	logger.Debugf("[%s] Peeked %d operations", q.serverInstanceID, len(items))

	return q.asQueuedOperations(items), nil
}

// Remove removes (up to) the given number of items from the head of the queue.
// Returns the actual number of items that were removed and the new length of the queue.
func (q *Queue) Remove(num uint) (ops operation.QueuedOperationsAtTime, ack func() uint, nack func(), err error) {
	if q.State() != lifecycle.StateStarted {
		return nil, nil, nil, lifecycle.ErrNotStarted
	}

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

	logger.Debugf("[%s] Removed %d operations", q.serverInstanceID, len(items))

	return q.asQueuedOperations(items), q.newAckFunc(items), q.newNackFunc(items), nil
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
	q.taskMgr.RegisterTask(taskID, q.taskMonitorInterval, q.monitorOtherServers)

	go q.listen()

	logger.Infof("Started operation queue")
}

func (q *Queue) listen() {
	logger.Debugf("Starting message listener")

	ticker := time.NewTicker(q.taskMonitorInterval)

	for {
		select {
		case msg, ok := <-q.msgChan:
			if !ok {
				logger.Debugf("Message listener stopped")

				return
			}

			q.handleMessage(msg)

		case <-ticker.C:
			// Update the task time so that other instances don't think I'm down.
			if err := q.updateTaskTime(q.serverInstanceID); err != nil {
				logger.Warnf("Error updating time on operation queue task: %w", err)
			}
		}
	}
}

func (q *Queue) handleMessage(msg *message.Message) {
	logger.Debugf("Handling operation message [%s]", msg.UUID)

	op := &OperationMessage{}

	err := q.unmarshal(msg.Payload, op)
	if err != nil {
		logger.Errorf("Error unmarshalling operation for message [%s]: %s", msg.UUID, err)

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	key := uuid.New().String()

	pop := persistedOperation{
		OperationMessage: op,
		ServerID:         q.serverInstanceID,
	}

	opBytes, err := json.Marshal(pop)
	if err != nil {
		logger.Errorf("Error marshalling operation for message [%s]: %s", msg.UUID, err)

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	err = q.store.Put(key, opBytes,
		storage.Tag{Name: tagServerID, Value: q.serverInstanceID},
	)
	if err != nil {
		logger.Warnf("Error storing operation info for [%s]. Message [%s] will be nacked and retried: %w",
			op.ID, msg.UUID, err)

		msg.Nack()

		return
	}

	q.mutex.Lock()
	defer q.mutex.Unlock()

	logger.Debugf("[%s] Adding operation to pending queue - ID [%s], DID [%s], Retries [%d]",
		q.serverInstanceID, op.ID, op.Operation.UniqueSuffix, op.Retries)

	q.pending = append(q.pending, &queuedOperation{
		OperationMessage: op,
		key:              key,
		timeAdded:        time.Now(),
	})

	msg.Ack()
}

func (q *Queue) newAckFunc(items []*queuedOperation) func() uint {
	return func() uint {
		logger.Infof("Committed %d operation messages...", len(items))

		if err := q.deleteOperations(items); err != nil {
			logger.Errorf("[%s] Error deleting pending operations: %s", q.serverInstanceID, err)
		} else {
			logger.Debugf("[%s] Deleted %d operations", q.serverInstanceID, len(items))
		}

		// Batch cut time is the time since the first operation was added (which is the oldest operation in the batch).
		q.metrics.BatchCutTime(time.Since(items[0].timeAdded))

		q.metrics.BatchSize(float64(len(items)))

		q.mutex.RLock()
		defer q.mutex.RUnlock()

		return uint(len(q.pending))
	}
}

func (q *Queue) newNackFunc(items []*queuedOperation) func() {
	return func() {
		logger.Infof("%d operations were rolled back. Re-posting...", len(items))

		var operationsToDelete []*queuedOperation

		for _, op := range items {
			if op.Retries >= q.maxRetries {
				logger.Warnf("... not re-posting operation [%s] for suffix [%s] since the retry count [%d] has reached the limit.",
					op.ID, op.Operation.UniqueSuffix, op.Retries)

				operationsToDelete = append(operationsToDelete, op)

				continue
			}

			op.Retries++

			logger.Infof("... re-posting operation [%s] for suffix [%s], retries [%d]",
				op.ID, op.Operation.UniqueSuffix, op.Retries)

			if _, err := q.publish(op.OperationMessage); err != nil {
				logger.Errorf("Error re-posting operation [%s]. Operation will be detached from this server instance: %s",
					op.ID, err)

				if e := q.detachOperation(op); e != nil {
					logger.Errorf("Failed to detach operation [%s] from this server instance: %s", op.ID, e)
				} else {
					logger.Infof("Operation [%s] was detached from this server instance since it could not be "+
						"published to the queue. It will be retried at a later time.", op.ID)
				}
			} else {
				operationsToDelete = append(operationsToDelete, op)
			}
		}

		if len(operationsToDelete) > 0 {
			if err := q.deleteOperations(operationsToDelete); err != nil {
				logger.Errorf("Error deleting operations: %s. Some (or all) of the operations "+
					"will be left in the database and potentially reprocessed (which should be harmless). "+
					"The operations should be deleted (at some point) by the data expiry service.", err)
			}
		}

		// Batch rollback time is the time since the first operation was added (which is the
		// oldest operation in the batch).
		q.metrics.BatchRollbackTime(time.Since(items[0].timeAdded))
	}
}

func (q *Queue) monitorOtherServers() {
	it, err := q.store.Query(tagOpQueueTask)
	if err != nil {
		logger.Warnf("Error querying for operation queue tasks: %w", err)

		return
	}

	defer storage.Close(it, logger)

	for {
		task, ok, err := q.nextTask(it)
		if err != nil {
			logger.Warnf("Error getting next operation queue task: %w", err)

			return
		}

		if !ok {
			break
		}

		if task.TaskID == q.serverInstanceID {
			// This is our queue task. Nothing to do.
			continue
		}

		q.repostOperationsForTask(task)
	}
}

func (q *Queue) repostOperationsForTask(task *opQueueTask) {
	if task.TaskID == detachedServerID {
		// Operations associated with the "detached" server ID are in error, most likely because the message
		// queue service is unavailable and the operations could not be re-published. Try to repost the operations.
		if err := q.repostOperations(task.TaskID); err != nil {
			logger.Warnf("[%s] Error reposting operations for server instance [%s]: %s",
				q.serverInstanceID, task.TaskID, err)
		}

		return
	}

	// This is not our task. Check to see if the server is still alive.
	timeSinceLastUpdate := time.Since(time.Unix(task.UpdatedTime, 0)).Truncate(time.Second)

	if timeSinceLastUpdate <= q.taskExpiration {
		return
	}

	logger.Warnf("[%s] Operation queue task [%s] was last updated %s ago which is longer than the expiry %s. "+
		"Assuming the server is dead and re-posting any outstanding operations to the queue.",
		q.serverInstanceID, task.TaskID, timeSinceLastUpdate, q.taskExpiration)

	if err := q.repostOperations(task.TaskID); err != nil {
		logger.Warnf("[%s] Error reposting operations for server instance [%s]: %s",
			q.serverInstanceID, task.TaskID, err)
	}
}

func (q *Queue) deleteOperations(items []*queuedOperation) error {
	batchOperations := make([]storage.Operation, len(items))

	for i, item := range items {
		batchOperations[i] = storage.Operation{
			Key: item.key,
		}
	}

	if err := q.store.Batch(batchOperations); err != nil {
		return fmt.Errorf("delete %d pending operations: %w", len(items), err)
	}

	return nil
}

func (q *Queue) asQueuedOperations(opMsgs []*queuedOperation) []*operation.QueuedOperationAtTime {
	ops := make([]*operation.QueuedOperationAtTime, len(opMsgs))

	logger.Debugf("[%s] Returning %d queued operations:", q.serverInstanceID, len(opMsgs))

	for i, opMsg := range opMsgs {
		logger.Debugf("[%s] - ID [%s], DID [%s]", q.serverInstanceID, opMsg.ID, opMsg.Operation.UniqueSuffix)

		ops[i] = opMsg.Operation
	}

	return ops
}

func (q *Queue) updateTaskTime(instanceID string) error {
	task := &opQueueTask{
		TaskID:      instanceID,
		UpdatedTime: time.Now().Unix(),
	}

	taskBytes, err := q.marshal(task)
	if err != nil {
		return fmt.Errorf("marshal operation queue task: %w", err)
	}

	err = q.store.Put(instanceID, taskBytes,
		storage.Tag{
			Name:  tagOpQueueTask,
			Value: instanceID,
		},
	)
	if err != nil {
		return fmt.Errorf("store operation queue task: %w", err)
	}

	return nil
}

func (q *Queue) repostOperations(serverID string) error { //nolint:gocyclo,cyclop
	it, err := q.store.Query(fmt.Sprintf("%s:%s", tagServerID, serverID))
	if err != nil {
		return fmt.Errorf("query operations with tag [%s]: %w", serverID, err)
	}

	defer storage.Close(it, logger)

	var batchOperations []storage.Operation

	for {
		key, op, ok, e := q.nextOperation(it)
		if e != nil {
			return fmt.Errorf("get nextOperation operation: %w", e)
		}

		if !ok {
			break
		}

		if op.Retries >= q.maxRetries {
			logger.Warnf("Not re-posting operation [%s] for suffix [%s] since the retry count [%d] has reached the limit.",
				op.ID, op.Operation.UniqueSuffix, op.Retries)

			continue
		}

		op.Retries++

		logger.Infof("[%s] Re-posting operation [%s] for suffix [%s]",
			q.serverInstanceID, op.ID, op.Operation.UniqueSuffix)

		if _, e = q.publish(op); e != nil {
			return fmt.Errorf("publish operation [%s]: %w", op.ID, e)
		}

		batchOperations = append(batchOperations, storage.Operation{Key: key})
	}

	if len(batchOperations) > 0 {
		logger.Infof("[%s] Deleting %d operations for queue task [%s]",
			q.serverInstanceID, len(batchOperations), serverID)

		err = q.store.Batch(batchOperations)
		if err != nil {
			return fmt.Errorf("delete operations: %w", err)
		}
	}

	if serverID != detachedServerID {
		logger.Infof("[%s] Deleting operation queue task [%s]", q.serverInstanceID, serverID)

		err = q.store.Delete(serverID)
		if err != nil {
			return fmt.Errorf("delete operation queue task [%s]: %w", q.serverInstanceID, err)
		}
	}

	return nil
}

func (q *Queue) nextTask(it storage.Iterator) (*opQueueTask, bool, error) {
	ok, err := it.Next()
	if err != nil {
		return nil, false, fmt.Errorf("get next operation queue tesk: %w", err)
	}

	if !ok {
		return nil, false, nil
	}

	opBytes, err := it.Value()
	if err != nil {
		return nil, false, fmt.Errorf("get next operation queue tesk: %w", err)
	}

	task := &opQueueTask{}

	err = q.unmarshal(opBytes, task)
	if err != nil {
		return nil, false, fmt.Errorf("unmarshal operation queue tesk: %w", err)
	}

	return task, true, nil
}

func (q *Queue) nextOperation(it storage.Iterator) (string, *OperationMessage, bool, error) {
	ok, err := it.Next()
	if err != nil {
		return "", nil, false, fmt.Errorf("get next operation: %w", err)
	}

	if !ok {
		return "", nil, false, nil
	}

	key, err := it.Key()
	if err != nil {
		return "", nil, false, fmt.Errorf("get operation ID from iterator: %w", err)
	}

	opBytes, err := it.Value()
	if err != nil {
		return "", nil, false, fmt.Errorf("get operation [%s]: %w", key, err)
	}

	op := &persistedOperation{}

	err = q.unmarshal(opBytes, op)
	if err != nil {
		return "", nil, false, fmt.Errorf("unmarshal operation [%s]: %w", key, err)
	}

	return key, op.OperationMessage, true, nil
}

func (q *Queue) detachOperation(op *queuedOperation) error {
	pop := &persistedOperation{
		OperationMessage: op.OperationMessage,
		ServerID:         detachedServerID,
	}

	opBytes, err := q.marshal(pop)
	if err != nil {
		return fmt.Errorf("marshal operation [%s]: %w", op.ID, err)
	}

	return q.store.Put(op.key, opBytes,
		storage.Tag{
			Name:  tagServerID,
			Value: detachedServerID,
		},
	)
}

func (q *Queue) getDeliveryDelay(attempts int) time.Duration {
	if attempts == 0 {
		return 0
	}

	if attempts == 1 {
		return q.redeliveryInitialInterval
	}

	interval := time.Duration(float64(q.redeliveryInitialInterval) * math.Pow(q.redeliveryMultiplier, float64(attempts-1)))

	if interval > q.maxRedeliveryInterval {
		interval = q.maxRedeliveryInterval
	}

	return interval
}

func resolveConfig(cfg Config) Config {
	if cfg.TaskMonitorInterval == 0 {
		cfg.TaskMonitorInterval = defaultInterval
	}

	if cfg.TaskExpiration == 0 {
		// Set the task expiration to a factor of the monitoring interval. So, if the monitoring interval is 10s and
		// the expiration factor is 2 then the task is considered to have expired after 20s.
		cfg.TaskExpiration = cfg.TaskMonitorInterval * defaultTaskExpirationFactor
	}

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}

	if cfg.RetriesInitialDelay == 0 {
		cfg.RetriesInitialDelay = defaultRetryInitialDelay
	}

	if cfg.RetriesMultiplier == 0 {
		cfg.RetriesMultiplier = defaultRetryMultiplier
	}

	if cfg.RetriesMaxDelay == 0 {
		cfg.RetriesMaxDelay = defaultMaxRetryDelay
	}

	return cfg
}
