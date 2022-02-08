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
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

var logger = log.New("sidetree_context")

const (
	topic          = "orb.operation"
	taskID         = "op-queue-monitorOtherServers"
	storeName      = "op-queue"
	tagOpExpiry    = "ExpiryTime"
	tagOpQueueTask = "Task"
	tagServerID    = "ServerID"

	defaultInterval             = 10 * time.Second
	defaultTaskExpirationFactor = 2
	defaultOpCleanupFactor      = 5
	defaultMaxRetries           = 10
)

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

type operationMessage struct {
	ID        string                           `json:"id"`
	Operation *operation.QueuedOperationAtTime `json:"operation"`
	Retries   int                              `json:"retries"`
}

type queuedOperation struct {
	*operationMessage

	key       string
	timeAdded time.Time
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

type dataExpiryService interface {
	Register(store storage.Store, expiryTagName, storeName string, opts ...expiry.Option)
}

type opQueueTask struct {
	// ServerID is the unique ID of the server instance.
	ServerID string `json:"serverID"`
	// UpdatedTime indicates when the status was last updated.
	UpdatedTime int64 `json:"updateTaskTime"` // This is a Unix timestamp.
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
	// OpExpiration is the age that a pending operation in the database is considered to have expired, after which the
	// operation is deleted. Operations should be deleted during normal processing but, in case it isn't deleted,
	// the data expiry service will delete the operations that are older than this value.
	OpExpiration time.Duration
	// MaxRetries is the maximum number of retries for a failed operation in a batch.
	MaxRetries int
}

// Queue implements an operation queue that uses a publisher/subscriber.
type Queue struct {
	*lifecycle.Lifecycle

	pubSub              pubSub
	msgChan             <-chan *message.Message
	mutex               sync.RWMutex
	pending             []*queuedOperation
	marshal             func(interface{}) ([]byte, error)
	unmarshal           func(data []byte, v interface{}) error
	metrics             metricsProvider
	serverInstanceID    string
	store               storage.Store
	taskMonitorInterval time.Duration
	taskExpiration      time.Duration
	opExpiration        time.Duration
	taskMgr             taskManager
	expiryService       dataExpiryService
	maxRetries          int
}

// New returns a new operation queue.
func New(cfg Config, pubSub pubSub, p storage.Provider, taskMgr taskManager,
	expiryService dataExpiryService, metrics metricsProvider) (*Queue, error) {
	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), topic, spi.WithPool(cfg.PoolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	s, err := p.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	err = p.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{tagOpQueueTask, tagOpExpiry}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	cfg = resolveConfig(cfg)

	q := &Queue{
		pubSub:              pubSub,
		msgChan:             msgChan,
		marshal:             json.Marshal,
		unmarshal:           json.Unmarshal,
		metrics:             metrics,
		serverInstanceID:    taskMgr.InstanceID(),
		store:               s,
		taskExpiration:      cfg.TaskExpiration,
		opExpiration:        cfg.OpExpiration,
		taskMonitorInterval: cfg.TaskMonitorInterval,
		taskMgr:             taskMgr,
		expiryService:       expiryService,
		maxRetries:          cfg.MaxRetries,
	}

	q.Lifecycle = lifecycle.New("operation-queue", lifecycle.WithStart(q.start))

	logger.Infof("[%s] Storing new operation queue task.", q.serverInstanceID)

	err = q.updateTaskTime()
	if err != nil {
		return nil, fmt.Errorf("update operation queue task time: %w", err)
	}

	return q, nil
}

// Add publishes the given operation.
func (q *Queue) Add(op *operation.QueuedOperation, protocolVersion uint64) (uint, error) {
	return q.post(
		&operationMessage{
			ID: uuid.New().String(),
			Operation: &operation.QueuedOperationAtTime{
				QueuedOperation: *op,
				ProtocolVersion: protocolVersion,
			},
		},
	)
}

func (q *Queue) post(op *operationMessage) (uint, error) {
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

	logger.Debugf("Publishing operation message to topic [%s] - Msg [%s], OpID [%s], DID [%s], Retries [%d]",
		topic, msg.UUID, op.ID, op.Operation.UniqueSuffix, op.Retries)

	err = q.pubSub.Publish(topic, msg)
	if err != nil {
		return 0, fmt.Errorf("publish queued operation: %w", err)
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

	q.expiryService.Register(q.store, tagOpExpiry, storeName)

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
			if err := q.updateTaskTime(); err != nil {
				logger.Warnf("Error updating time on operation queue task: %w", err)
			}
		}
	}
}

func (q *Queue) handleMessage(msg *message.Message) {
	logger.Debugf("Handling operation message [%s]", msg.UUID)

	op := &operationMessage{}

	err := q.unmarshal(msg.Payload, op)
	if err != nil {
		logger.Errorf("Error unmarshalling operation: %s", err)

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	key := uuid.New().String()

	err = q.store.Put(key, msg.Payload,
		storage.Tag{
			Name:  tagServerID,
			Value: q.serverInstanceID,
		},
		storage.Tag{
			Name:  tagOpExpiry,
			Value: fmt.Sprintf("%d", time.Now().Add(q.opExpiration).Unix()),
		},
	)
	if err != nil {
		logger.Warnf("Error storing operation info. The message will be nacked and retried: %w", err)

		msg.Nack()

		return
	}

	q.mutex.Lock()
	defer q.mutex.Unlock()

	logger.Debugf("[%s] Adding operation to pending queue - ID [%s], DID [%s], Retries [%d]",
		q.serverInstanceID, op.ID, op.Operation.UniqueSuffix, op.Retries)

	q.pending = append(q.pending, &queuedOperation{
		operationMessage: op,
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

		for _, op := range items {
			if op.Retries >= q.maxRetries {
				logger.Warnf("... not re-posting operation [%s] for suffix [%s] since the retry count [%d] has reached the limit.",
					op.ID, op.Operation.UniqueSuffix, op.Retries)

				continue
			}

			op.Retries++

			logger.Infof("... re-posting operation [%s] for suffix [%s], retries [%d]",
				op.ID, op.Operation.UniqueSuffix, op.Retries)

			if _, err := q.post(op.operationMessage); err != nil {
				logger.Errorf("Error re-posting operation [%s]", op.ID)

				return
			}
		}

		if err := q.deleteOperations(items); err != nil {
			logger.Errorf("Error deleting operations: %s. Some (or all) of the operations "+
				"will be left in the database and potentially reprocessed (which should be harmless). "+
				"The operations should be deleted (at some point) by the data expiry service.", err)
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

		if task.ServerID == q.serverInstanceID {
			// This is our queue task. Nothing to do.
			continue
		}

		// This is not our task. Check to see if the server is still alive.
		timeSinceLastUpdate := time.Since(time.Unix(task.UpdatedTime, 0)).Truncate(time.Second)

		if timeSinceLastUpdate > q.taskExpiration {
			logger.Warnf("[%s] Operation queue task [%s] was last updated %s ago which is longer than the expiry %s. "+
				"Assuming the server is dead and re-posting any outstanding operations to the queue.",
				q.serverInstanceID, task.ServerID, timeSinceLastUpdate, q.taskExpiration)

			err = q.repostOperations(task.ServerID)
			if err != nil {
				logger.Warnf("[%s] Error reposting operations for server instance [%s]: %s",
					q.serverInstanceID, task.ServerID, err)

				return
			}
		}
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

func (q *Queue) updateTaskTime() error {
	task := &opQueueTask{
		ServerID:    q.serverInstanceID,
		UpdatedTime: time.Now().Unix(),
	}

	taskBytes, err := q.marshal(task)
	if err != nil {
		return fmt.Errorf("marshal operation queue task: %w", err)
	}

	err = q.store.Put(q.serverInstanceID, taskBytes, storage.Tag{Name: tagOpQueueTask})
	if err != nil {
		return fmt.Errorf("store operation queue task: %w", err)
	}

	return nil
}

func (q *Queue) repostOperations(serverID string) error {
	it, err := q.store.Query(fmt.Sprintf("%s:%s", tagServerID, serverID))
	if err != nil {
		return fmt.Errorf("query operations with tag [%s]: %w", serverID, err)
	}

	defer storage.Close(it, logger)

	var batchOperations []storage.Operation

	for {
		key, op, ok, e := q.nextOperation(it)
		if e != nil {
			return fmt.Errorf("get nextOperation operation: %w", err)
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

		logger.Debugf("[%s] Re-posting operation [%s] for suffix [%s]",
			q.serverInstanceID, op.ID, op.Operation.UniqueSuffix)

		_, e = q.post(op)
		if e != nil {
			return fmt.Errorf("unmarshal operation [%s]: %w", op.ID, e)
		}

		batchOperations = append(batchOperations, storage.Operation{Key: key})
	}

	logger.Infof("[%s] Deleting operation queue task [%s]", q.serverInstanceID, serverID)

	if len(batchOperations) > 0 {
		logger.Infof("[%s] Deleting %d operations for queue task [%s]",
			q.serverInstanceID, len(batchOperations), serverID)

		err = q.store.Batch(batchOperations)
		if err != nil {
			return fmt.Errorf("delete operations: %w", err)
		}
	}

	err = q.store.Delete(serverID)
	if err != nil {
		return fmt.Errorf("delete operation queue task [%s]: %w", q.serverInstanceID, err)
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

func (q *Queue) nextOperation(it storage.Iterator) (string, *operationMessage, bool, error) {
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

	op := &operationMessage{}

	err = q.unmarshal(opBytes, op)
	if err != nil {
		return "", nil, false, fmt.Errorf("unmarshal operation [%s]: %w", key, err)
	}

	return key, op, true, nil
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

	if cfg.OpExpiration == 0 {
		// Set the cleanup interval to a factor of the task expiration interval. So, if the task expiration interval
		// is 20s and the cleanup factor is 5 then the operation is considered to have expired after 100s.
		cfg.OpExpiration = cfg.TaskExpiration * defaultOpCleanupFactor
	}

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}

	return cfg
}
