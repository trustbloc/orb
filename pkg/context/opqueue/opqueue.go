/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	svcoperation "github.com/trustbloc/sidetree-svc-go/pkg/api/operation"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/anchor/multierror"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	"github.com/trustbloc/orb/pkg/pubsub"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/store"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	loggerModule = "sidetree_context"

	topic            = "orb.operation"
	taskID           = "op-queue-monitor"
	storeName        = "operation-queue"
	tagOpQueueTask   = "taskID"
	tagServerID      = "serverID"
	tagExpiryTime    = "expiryTime"
	detachedServerID = "detached"

	defaultInterval                 = 10 * time.Second
	defaultTaskExpirationFactor     = 3
	defaultMaxRetries               = 10
	defaultRetryInitialDelay        = 2 * time.Second
	defaultMaxRetryDelay            = 30 * time.Second
	defaultRetryMultiplier          = 1.5
	defaultMaxOperationsToRepost    = 1000
	defaultOperationLifespan        = 10 * time.Minute
	defaultMaxContiguousWithError   = 10000
	defaultMaxContiguousWithNoError = 10000
	defaultDelayPadding             = 5 * time.Second

	propCreatePublished = "create-op-is-published"
)

type pubSub interface {
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	PublishWithOpts(topic string, msg *message.Message, opts ...spi.Option) error
	Close() error
}

// OperationMessage contains the data that is sent to the message broker.
type OperationMessage struct {
	ID        string                              `json:"id"`
	Operation *svcoperation.QueuedOperationAtTime `json:"operation"`
	Retries   int                                 `json:"retries"`
	HasError  bool                                `json:"hasError,omitempty"`
}

type queuedOperation struct {
	*OperationMessage

	key       string
	timeAdded time.Time
}

//nolint:tagliatelle
type persistedOperation struct {
	*OperationMessage

	ServerID   string `json:"serverID"`
	ExpiryTime int64  `json:"expiryTime"`
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

//nolint:tagliatelle
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
	// MaxOperationsToRepost is the maximum number of operations to repost to the queue after
	// an instance dies.
	MaxOperationsToRepost int
	// OperationLifespan is the maximum time that an operation can exist in the database before
	// it is deleted
	OperationLifeSpan time.Duration
	// BatchWriterTimeout specifies the timeout for when a batch of operations is cut.
	BatchWriterTimeout time.Duration
	// MaxContiguousWithError specifies the maximum number of previously failed operations to rearrange contiguously.
	MaxContiguousWithError int
	// MaxContiguousWithoutError specifies the maximum number of operations (with no error) to rearrange contiguously.
	MaxContiguousWithoutError int
}

// Queue implements an operation queue that uses a publisher/subscriber.
type Queue struct {
	*lifecycle.Lifecycle

	pubSub                    pubSub
	msgChan                   <-chan *message.Message
	pending                   *queuedOperations
	marshal                   func(interface{}) ([]byte, error)
	unmarshal                 func(data []byte, v interface{}) error
	metrics                   metricsProvider
	serverInstanceID          string
	store                     storage.Store
	taskMonitorInterval       time.Duration
	taskExpiration            time.Duration
	taskMgr                   taskManager
	expiryService             dataExpiryService
	maxRetries                int
	redeliveryInitialInterval time.Duration
	maxRedeliveryInterval     time.Duration
	redeliveryMultiplier      float64
	maxOperationsToRepost     int
	logger                    *log.Log
	tracer                    trace.Tracer
	operationLifeSpan         time.Duration
	delayForUnpublishedCreate time.Duration
}

// New returns a new operation queue.
func New(cfg *Config, pubSub pubSub, p storage.Provider, taskMgr taskManager,
	expiryService dataExpiryService, metrics metricsProvider,
) (*Queue, error) {
	logger := log.New(loggerModule, log.WithFields(logfields.WithTaskMgrInstanceID(taskMgr.InstanceID())))

	msgChan, err := pubSub.SubscribeWithOpts(context.Background(), topic, spi.WithPool(cfg.PoolSize))
	if err != nil {
		return nil, fmt.Errorf("subscribe to topic [%s]: %w", topic, err)
	}

	s, err := store.Open(p, storeName,
		store.NewTagGroup(tagOpQueueTask),
		store.NewTagGroup(tagExpiryTime),
	)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	cfg = resolveConfig(cfg)

	logger.Info("Creating operation queue.",
		log.WithTopic(topic), logfields.WithMaxRetries(cfg.MaxRetries), logfields.WithSubscriberPoolSize(cfg.PoolSize),
		logfields.WithTaskMonitorInterval(cfg.TaskMonitorInterval), logfields.WithTaskExpiration(cfg.TaskExpiration),
		logfields.WithMaxOperationsToRepost(cfg.MaxOperationsToRepost))

	pendingQueue := newQueuedOperations(cfg.MaxContiguousWithError, cfg.MaxContiguousWithoutError, logger)

	q := &Queue{
		pending:                   pendingQueue,
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
		expiryService:             expiryService,
		maxRetries:                cfg.MaxRetries,
		redeliveryInitialInterval: cfg.RetriesInitialDelay,
		redeliveryMultiplier:      cfg.RetriesMultiplier,
		maxRedeliveryInterval:     cfg.RetriesMaxDelay,
		maxOperationsToRepost:     cfg.MaxOperationsToRepost,
		operationLifeSpan:         cfg.OperationLifeSpan,
		delayForUnpublishedCreate: cfg.BatchWriterTimeout + defaultDelayPadding,
		logger:                    logger,
		tracer:                    tracing.Tracer(tracing.SubsystemOperationQueue),
	}

	q.Lifecycle = lifecycle.New("operation-queue", lifecycle.WithStart(q.start))

	logger.Info("Storing new operation queue task.")

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
func (q *Queue) Add(op *svcoperation.QueuedOperation, protocolVersion uint64) (uint, error) {
	ctx, span := q.tracer.Start(context.Background(), "add operation",
		trace.WithAttributes(tracing.DIDSuffixAttribute(op.UniqueSuffix)),
	)
	defer span.End()

	return q.publish(
		ctx,
		&OperationMessage{
			ID: uuid.New().String(),
			Operation: &svcoperation.QueuedOperationAtTime{
				QueuedOperation: *op,
				ProtocolVersion: protocolVersion,
			},
		},
	)
}

func (q *Queue) publish(ctx context.Context, op *OperationMessage) (uint, error) {
	if q.State() != lifecycle.StateStarted {
		return 0, lifecycle.ErrNotStarted
	}

	startTime := time.Now()

	defer func() {
		q.metrics.AddOperationTime(time.Since(startTime))
	}()

	b, err := q.marshal(op)
	if err != nil {
		return 0, fmt.Errorf("marshal queued operation: %w", err)
	}

	msg := pubsub.NewMessage(ctx, b)

	delay, err := q.getDeliveryDelay(op)
	if err != nil {
		return 0, fmt.Errorf("get delivery delay: %w", err)
	}

	q.logger.Debugc(ctx, "Publishing operation message to queue", log.WithTopic(topic), logfields.WithMessageID(msg.UUID),
		logfields.WithOperationID(op.ID), logfields.WithRetries(op.Retries), logfields.WithDeliveryDelay(delay),
		logfields.WithSuffix(op.Operation.UniqueSuffix))

	err = q.pubSub.PublishWithOpts(topic, msg, spi.WithDeliveryDelay(delay))
	if err != nil {
		return 0, fmt.Errorf("publish queued operation [%s]: %w", op.ID, err)
	}

	return 0, nil
}

// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
func (q *Queue) Peek(num uint) (svcoperation.QueuedOperationsAtTime, error) {
	if q.State() != lifecycle.StateStarted {
		return nil, lifecycle.ErrNotStarted
	}

	q.pending.deFragment()

	items := q.pending.Peek(num)

	q.logger.Debug("Peeked operations.", logfields.WithTotal(len(items)))

	return q.asQueuedOperations(items), nil
}

// Remove removes (up to) the given number of items from the head of the queue.
// Returns the actual number of items that were removed and the new length of the queue.
func (q *Queue) Remove(num uint) (ops svcoperation.QueuedOperationsAtTime, ack func() uint, nack func(error), err error) {
	if q.State() != lifecycle.StateStarted {
		return nil, nil, nil, lifecycle.ErrNotStarted
	}

	items := q.pending.Remove(num)
	if len(items) == 0 {
		return nil,
			func() uint { return 0 },
			func(error) {}, nil
	}

	q.logger.Debug("Removed operations.", logfields.WithTotal(len(items)))

	return q.asQueuedOperations(items), q.newAckFunc(items), q.newNackFunc(items), nil
}

// Len returns the length of the pending queue.
func (q *Queue) Len() uint {
	if q.State() != lifecycle.StateStarted {
		return 0
	}

	return q.pending.Len()
}

func (q *Queue) start() {
	q.taskMgr.RegisterTask(taskID, q.taskMonitorInterval, q.monitorOtherServers)
	q.expiryService.Register(q.store, tagExpiryTime, storeName)

	go q.listen()

	q.logger.Info("Started operation queue")
}

func (q *Queue) listen() {
	q.logger.Debug("Starting message listener")

	ticker := time.NewTicker(q.taskMonitorInterval)

	for {
		select {
		case msg, ok := <-q.msgChan:
			if !ok {
				q.logger.Debug("Message listener stopped")

				return
			}

			go q.handleMessage(msg)

		case <-ticker.C:
			// Update the task time so that other instances don't think I'm down.
			if err := q.updateTaskTime(q.serverInstanceID); err != nil {
				q.logger.Warn("Error updating time on operation queue task", log.WithError(err))
			}
		}
	}
}

func (q *Queue) handleMessage(msg *message.Message) {
	q.logger.Debug("Handling operation message", logfields.WithMessageID(msg.UUID))

	op := &OperationMessage{}

	err := q.unmarshal(msg.Payload, op)
	if err != nil {
		q.logger.Error("Error unmarshalling operation message payload.",
			logfields.WithMessageID(msg.UUID), log.WithError(err))

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	key := uuid.New().String()

	pop := persistedOperation{
		OperationMessage: op,
		ServerID:         q.serverInstanceID,
		ExpiryTime:       time.Now().Add(q.operationLifeSpan).Unix(),
	}

	opBytes, err := q.marshal(pop)
	if err != nil {
		q.logger.Error("Error marshalling operation.", logfields.WithMessageID(msg.UUID), log.WithError(err))

		// Send an Ack so that the message is not retried.
		msg.Ack()

		return
	}

	err = q.store.Put(key, opBytes,
		storage.Tag{Name: tagServerID, Value: q.serverInstanceID},
		storage.Tag{Name: tagExpiryTime, Value: fmt.Sprintf("%d", pop.ExpiryTime)},
	)
	if err != nil {
		q.logger.Warn("Error storing operation info. Message will be nacked and retried.",
			logfields.WithOperationID(op.ID), logfields.WithMessageID(msg.UUID), log.WithError(err))

		msg.Nack()

		return
	}

	q.logger.Debug("Adding operation to pending queue", logfields.WithOperationID(op.ID),
		logfields.WithSuffix(op.Operation.UniqueSuffix), logfields.WithRetries(op.Retries))

	q.pending.Add(&queuedOperation{
		OperationMessage: op,
		key:              key,
		timeAdded:        time.Now(),
	})

	msg.Ack()
}

func (q *Queue) newAckFunc(items []*queuedOperation) func() uint {
	return func() uint {
		if err := q.deleteOperations(items); err != nil {
			q.logger.Error("Error deleting pending operations after ACK.", logfields.WithTotal(len(items)), log.WithError(err))
		} else {
			q.logger.Debug("Deleted operations after ACK.", logfields.WithTotal(len(items)))
		}

		// Batch cut time is the time since the first operation was added (which is the oldest operation in the batch).
		q.metrics.BatchCutTime(time.Since(items[0].timeAdded))

		q.metrics.BatchSize(float64(len(items)))

		return q.pending.Len()
	}
}

func (q *Queue) newNackFunc(items []*queuedOperation) func(error) {
	return func(err error) {
		ctx, span := q.tracer.Start(context.Background(), "nack")
		defer span.End()

		q.logger.Infoc(ctx, "Operations were rolled back. Re-posting...", logfields.WithTotal(len(items)),
			log.WithError(err))

		var mErr *multierror.Error

		if ok := errors.As(err, &mErr); ok {
			if log.GetLevel(loggerModule) == log.DEBUG {
				for suffix, e := range mErr.Errors() {
					q.logger.Debug("DID operation error", logfields.WithSuffix(suffix), log.WithError(e))
				}
			}
		}

		var operationsToDelete []*queuedOperation

		for _, op := range items {
			if op.Retries >= q.maxRetries {
				q.logger.Warnc(ctx, "Not re-posting operation after NACK since the retry count has reached the limit.",
					logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix),
					logfields.WithRetries(op.Retries), logfields.WithMaxRetries(q.maxRetries))

				operationsToDelete = append(operationsToDelete, op)

				continue
			}

			op.Retries++

			errSuffix, ok := mErr.Errors()[op.Operation.UniqueSuffix]
			op.HasError = ok

			q.logger.Infoc(ctx, "Re-posting operation after NACK", logfields.WithOperationID(op.ID),
				logfields.WithSuffix(op.Operation.UniqueSuffix), logfields.WithRetries(op.Retries),
				logfields.WithMaxRetries(q.maxRetries), log.WithError(errSuffix))

			if _, err := q.publish(ctx, op.OperationMessage); err != nil {
				q.logger.Errorc(ctx, "Error re-posting operation after NACK. Operation will be detached from this server instance",
					logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix), log.WithError(err))

				if e := q.detachOperation(op); e != nil {
					q.logger.Errorc(ctx, "Failed to detach operation from this server instance",
						logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix), log.WithError(e))
				} else {
					q.logger.Infoc(ctx, "Operation was detached from this server instance since it could not be "+
						"published to the queue. It will be retried at a later time.",
						logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix))
				}
			} else {
				operationsToDelete = append(operationsToDelete, op)
			}
		}

		if len(operationsToDelete) > 0 {
			if err := q.deleteOperations(operationsToDelete); err != nil {
				q.logger.Errorc(ctx, "Error deleting operations after NACK. Some (or all) of the operations "+
					"will be left in the database and potentially reprocessed (which should be harmless). "+
					"The operations should be deleted (at some point) by the data expiry service.", log.WithError(err))
			} else {
				q.logger.Debugc(ctx, "Deleted operations after NACK", logfields.WithTotal(len(operationsToDelete)))
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
		q.logger.Warn("Error querying for operation queue tasks", log.WithError(err))

		return
	}

	defer store.CloseIterator(it)

	for {
		task, ok, err := q.nextTask(it)
		if err != nil {
			q.logger.Warn("Error getting next operation queue task", log.WithError(err))

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
			q.logger.Warn("Error reposting operations", logfields.WithPermitHolder(task.TaskID), log.WithError(err))
		}

		return
	}

	// This is not our task. Check to see if the server is still alive.
	timeSinceLastUpdate := time.Since(time.Unix(task.UpdatedTime, 0)).Truncate(time.Second)

	if timeSinceLastUpdate <= q.taskExpiration {
		return
	}

	q.logger.Warn("Operation queue task was last updated a while ago (longer than the expiry). "+
		"Assuming the server is dead and re-posting any outstanding operations to the queue.",
		logfields.WithPermitHolder(task.TaskID), logfields.WithTimeSinceLastUpdate(timeSinceLastUpdate),
		logfields.WithTaskExpiration(q.taskExpiration))

	if err := q.repostOperations(task.TaskID); err != nil {
		q.logger.Warn("Error reposting operations for other server instance",
			logfields.WithPermitHolder(task.TaskID), log.WithError(err))
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

func (q *Queue) asQueuedOperations(opMsgs []*queuedOperation) []*svcoperation.QueuedOperationAtTime {
	ops := make([]*svcoperation.QueuedOperationAtTime, len(opMsgs))

	q.logger.Debug("Returning queued operations", logfields.WithTotal(len(opMsgs)))

	for i, opMsg := range opMsgs {
		q.logger.Debug("Adding operation.", logfields.WithOperationID(opMsg.ID),
			logfields.WithSuffix(opMsg.Operation.UniqueSuffix))

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

func (q *Queue) repostOperations(serverID string) error { //nolint:cyclop
	it, err := q.store.Query(fmt.Sprintf("%s:%s", tagServerID, serverID))
	if err != nil {
		return fmt.Errorf("query operations with tag [%s]: %w", serverID, err)
	}

	defer store.CloseIterator(it)

	span := tracing.NewSpan(q.tracer, context.Background())
	defer span.End()

	deleteQueueTask := serverID != detachedServerID

	var operationsToDelete []storage.Operation

	for {
		key, op, ok, e := q.nextOperation(it)
		if e != nil {
			return fmt.Errorf("get nextOperation operation: %w", e)
		}

		if !ok {
			break
		}

		if op.Retries >= q.maxRetries {
			q.logger.Warn("Not re-posting operation since the retry count has reached the limit.",
				logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix),
				logfields.WithRetries(op.Retries))

			operationsToDelete = append(operationsToDelete, storage.Operation{Key: key})

			continue
		}

		op.Retries++

		q.logger.Info("Re-posting operation for queue task.", logfields.WithOperationID(op.ID),
			logfields.WithSuffix(op.Operation.UniqueSuffix), logfields.WithPermitHolder(serverID))

		if _, e = q.publish(span.Start("re-post operations"), op); e != nil {
			q.logger.Error("Error re-posting operation", logfields.WithOperationID(op.ID), log.WithError(e),
				logfields.WithSuffix(op.Operation.UniqueSuffix), logfields.WithPermitHolder(serverID))

			deleteQueueTask = false

			break
		}

		operationsToDelete = append(operationsToDelete, storage.Operation{Key: key})

		if len(operationsToDelete) >= q.maxOperationsToRepost {
			q.logger.Info("Reached max number of operations to re-post in this task run", log.WithError(e),
				logfields.WithOperationID(op.ID), logfields.WithSuffix(op.Operation.UniqueSuffix),
				logfields.WithMaxOperationsToRepost(q.maxOperationsToRepost), logfields.WithPermitHolder(serverID))

			deleteQueueTask = false

			break
		}
	}

	if len(operationsToDelete) > 0 {
		q.logger.Info("Deleting operations for queue task after re-posting to MQ.", logfields.WithTotal(len(operationsToDelete)),
			logfields.WithPermitHolder(serverID))

		err = q.store.Batch(operationsToDelete)
		if err != nil {
			return fmt.Errorf("delete operations: %w", err)
		}
	}

	if deleteQueueTask {
		q.logger.Info("Deleting operation queue task.", logfields.WithPermitHolder(serverID))

		err = q.store.Delete(serverID)
		if err != nil {
			return fmt.Errorf("delete operation queue task [%s]: %w", serverID, err)
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
		ExpiryTime:       time.Now().Add(q.operationLifeSpan).Unix(),
	}

	opBytes, err := q.marshal(pop)
	if err != nil {
		return fmt.Errorf("marshal operation [%s]: %w", op.ID, err)
	}

	return q.store.Put(op.key, opBytes,
		storage.Tag{Name: tagServerID, Value: detachedServerID},
		storage.Tag{Name: tagExpiryTime, Value: fmt.Sprintf("%d", pop.ExpiryTime)},
	)
}

func (q *Queue) getDeliveryDelay(op *OperationMessage) (time.Duration, error) {
	if op.Operation.Type == operation.TypeCreate {
		return 0, nil
	}

	published, err := isCreatePublished(op.Operation.Properties)
	if err != nil {
		return 0, err
	}

	if published {
		return 0, nil
	}

	q.logger.Debug("Adding delay to the operation since the 'Create' operation was not published. "+
		"This operation will be processed in a subsequent batch.",
		logfields.WithSuffix(op.Operation.UniqueSuffix), logfields.WithOperationType(string(op.Operation.Type)),
		logfields.WithDeliveryDelay(q.delayForUnpublishedCreate))

	return q.delayForUnpublishedCreate, nil
}

func resolveConfig(cfg *Config) *Config {
	if cfg.TaskMonitorInterval == 0 {
		cfg.TaskMonitorInterval = defaultInterval
	}

	if cfg.TaskExpiration == 0 {
		// Set the task expiration to a factor of the monitoring interval. So, if the monitoring interval is 10s and
		// the expiration factor is 3 then the task is considered to have expired after 60s.
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

	if cfg.MaxOperationsToRepost == 0 {
		cfg.MaxOperationsToRepost = defaultMaxOperationsToRepost
	}

	if cfg.OperationLifeSpan == 0 {
		cfg.OperationLifeSpan = defaultOperationLifespan
	}

	if cfg.MaxContiguousWithError == 0 {
		cfg.MaxContiguousWithError = defaultMaxContiguousWithError
	}

	if cfg.MaxContiguousWithoutError == 0 {
		cfg.MaxContiguousWithoutError = defaultMaxContiguousWithNoError
	}

	return cfg
}

type queuedOperations struct {
	ops    []*queuedOperation
	mutex  sync.RWMutex
	logger *log.Log

	maxContguousWithError     int
	maxContiguousWithoutError int
}

func newQueuedOperations(maxContiguousWithError, maxContiguousWithoutError int, logger *log.Log) *queuedOperations {
	return &queuedOperations{
		logger:                    logger,
		maxContguousWithError:     maxContiguousWithError,
		maxContiguousWithoutError: maxContiguousWithoutError,
	}
}

func (o *queuedOperations) Add(op *queuedOperation) {
	o.mutex.Lock()
	o.ops = append(o.ops, op)
	o.mutex.Unlock()
}

func (o *queuedOperations) Remove(num uint) []*queuedOperation {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	return o.retrieve(num, true)
}

func (o *queuedOperations) Peek(num uint) []*queuedOperation {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	return o.retrieve(num, false)
}

func (o *queuedOperations) retrieve(n uint, remove bool) []*queuedOperation {
	num := int(n)

	actualNum := o.num()
	if actualNum < num {
		num = actualNum
	}

	var items []*queuedOperation

	if num > 0 {
		items = o.ops[0:num]

		if remove {
			o.ops = o.ops[num:]
		}
	}

	return items
}

func (o *queuedOperations) Len() uint {
	o.mutex.RLock()
	defer o.mutex.RUnlock()

	// Return the length of all operations (in all error states). Even though only the operations in
	// a homogeneous state are returned, we want to give the batch writer the total number so that
	// the queue doesn't back up.
	return uint(len(o.ops))
}

type errorState int

func toErrorState(has bool) errorState {
	if has {
		return 1
	}

	return 0
}

func (s errorState) Bool() bool {
	return s == 1
}

const initialErrState errorState = -1

// num iterates through the operations and returns the number of operations which are at the same error state.
func (o *queuedOperations) num() int {
	if len(o.ops) == 0 {
		return 0
	}

	n := 0
	errState := initialErrState

	for _, op := range o.ops {
		if errState == initialErrState {
			errState = toErrorState(op.HasError)
		}

		if toErrorState(op.HasError) != errState {
			break
		}

		n++
	}

	return n
}

// deFragment de-fragments the operation queue such that operations that have previously failed are grouped
// contiguously and operations that have no error (thus far) are also grouped contiguously. Grouping (de-fragmenting)
// the operation queue provides a greater chance that valid operations are successfully processed and are not
// failed just because the batch failed due to a single "bad" operation.
func (o *queuedOperations) deFragment() {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	deFragment(o.ops, o.getMax)
}

func (o *queuedOperations) getMax(v bool) int {
	if v {
		return o.maxContguousWithError
	}

	return o.maxContiguousWithoutError
}

func swap(a []*queuedOperation, dest, src int) {
	a[dest], a[src] = a[src], a[dest]
}

func shift(a []*queuedOperation, dest, src int) {
	for i := src; i > dest; i-- {
		swap(a, i-1, i)
	}
}

func find(a []*queuedOperation, from int, v bool) (int, bool) {
	for i := from; i < len(a); i++ {
		if a[i].HasError == v {
			return i, true
		}
	}

	return -1, false
}

func deFragment(a []*queuedOperation, getMax func(v bool) int) {
	if len(a) == 0 {
		return
	}

	errState := a[0].HasError

	for i := 0; i < getMax(errState); i++ {
		n, ok := find(a, i, errState)
		if !ok {
			return
		}

		if n != i {
			shift(a, i, n)
		}
	}
}

func isCreatePublished(properties []operation.Property) (bool, error) {
	for _, prop := range properties {
		if prop.Key == propCreatePublished {
			published, ok := prop.Value.(bool)
			if !ok {
				return false, fmt.Errorf("operation property value is not of type bool: %s", propCreatePublished)
			}

			return published, nil
		}
	}

	return false, fmt.Errorf("operation property not found: %s", propCreatePublished)
}
