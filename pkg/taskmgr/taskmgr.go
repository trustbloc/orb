/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package taskmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	coordinationPermitKey = "task-permit"
	defaultCheckInterval  = 10 * time.Second
)

type status = string

const (
	loggerModule = "task-manager"

	statusIdle    status = "idle"
	statusRunning status = "running"
)

// permit is used as an entry within the coordination store to ensure that only one Orb instance
// within a cluster has the duty of running tasks periodically.
//
//nolint:tagliatelle
type permit struct {
	// TaskID is the ID of the task that is being run.
	TaskID string `json:"task_id"`
	// CurrentHolder indicates which Orb server currently has the responsibility.
	CurrentHolder string `json:"currentHolder"`
	// Status indicates the current status (idle or running).
	Status string `json:"status"`
	// UpdatedTime indicates when the status was last updated.
	UpdatedTime int64 `json:"updateTime"` // This is a Unix timestamp.
}

// Manager manages scheduled tasks which are run by exactly one server instance in an Orb domain.
type Manager struct {
	*lifecycle.Lifecycle

	interval          time.Duration
	tasks             map[string]*registration
	done              chan struct{}
	logger            *log.Log
	coordinationStore storage.Store
	instanceID        string
	mutex             sync.RWMutex
}

// New returns a new task manager.
// coordinationStore is used for ensuring that only one Orb instance within a cluster has the duty of running scheduled
// tasks (in order to avoid every instance doing the same work, which is wasteful). Every Orb instance
// within the cluster needs to be connected to the same database for it to work correctly. Note that when initializing
// Orb servers (or if the Orb server with the duty goes down) it is possible for multiple Orb instances to briefly
// assign themselves the duty, but only for one round. This will automatically be resolved on
// the next check and only one will end up with the duty from that point on. This situation should not be of concern
// since a task should expect this situation.
// You must register each task you want this service to run on using the Register method.
// Start must be called to start the service and Stop should be called to stop it.
func New(coordinationStore storage.Store, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = defaultCheckInterval
	}

	instanceID := uuid.New().String()

	s := &Manager{
		interval:          interval,
		done:              make(chan struct{}),
		logger:            log.New(loggerModule, log.WithFields(log.WithTaskMgrInstanceID(instanceID))),
		coordinationStore: coordinationStore,
		instanceID:        instanceID,
		tasks:             make(map[string]*registration),
	}

	s.Lifecycle = lifecycle.New("task-manager",
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop))

	return s
}

// InstanceID returns the unique ID of this server instance.
func (s *Manager) InstanceID() string {
	return s.instanceID
}

// RegisterTask registers a task to be periodically run at the given interval.
func (s *Manager) RegisterTask(id string, interval time.Duration, task func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.tasks[id] = &registration{
		handle:   task,
		id:       id,
		interval: interval,
	}
}

func (s *Manager) getTasks() []*registration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var tasks []*registration

	for _, t := range s.tasks {
		tasks = append(tasks, t)
	}

	return tasks
}

func (s *Manager) start() {
	go func() {
		s.logger.Info("Started task manager.")

		for {
			select {
			case <-time.After(s.interval):
				for _, t := range s.getTasks() {
					if err := s.run(t); err != nil {
						s.logger.Error("Error running task", log.WithError(err), log.WithTaskID(t.id))
					}
				}
			case <-s.done:
				s.logger.Debug("Stopped task manager.")

				return
			}
		}
	}()
}

func (s *Manager) stop() {
	close(s.done)
}

func (s *Manager) run(t *registration) error {
	if t.isRunning() {
		s.logger.Debug("Task is still running. Updating timestamp in the permit to tell others that I'm still alive.",
			log.WithTaskID(t.id))

		if err := s.updatePermit(t.id, statusRunning); err != nil {
			s.logger.Warn("Error updating status of task", log.WithTaskID(t.id), log.WithError(err))
		}

		return nil
	}

	ok, err := s.shouldRun(t)
	if err != nil {
		return fmt.Errorf("should run: %w", err)
	}

	if !ok {
		s.logger.Debug("Not running task.", log.WithTaskID(t.id))

		return nil
	}

	err = s.updatePermit(t.id, statusRunning)
	if err != nil {
		return fmt.Errorf("update permit for task: %w", err)
	}

	// Run the task in a new Go routine.

	go func(t *registration) {
		s.logger.Debug("Running task", log.WithTaskID(t.id))

		t.run()

		err := s.updatePermit(t.id, statusIdle)
		if err != nil {
			s.logger.Error("Failed to update permit for task", log.WithTaskID(t.id), log.WithError(err))
		}

		s.logger.Debug("Finished running task", log.WithTaskID(t.id))
	}(t)

	return nil
}

func (s *Manager) shouldRun(t *registration) (bool, error) {
	currentPermitBytes, err := s.coordinationStore.Get(getPermitKey(t.id))
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			s.logger.Info("No existing permit found for task. I will take on the duty of running the task.",
				log.WithTaskID(t.id))

			return true, nil
		}

		return false, fmt.Errorf("get permit from DB for task [%s]: %w", t.id, err)
	}

	var currentPermit permit

	err = json.Unmarshal(currentPermitBytes, &currentPermit)
	if err != nil {
		return false, fmt.Errorf("unmarshal permit for task [%s]: %w", t.id, err)
	}

	timeOfLastUpdate := time.Unix(currentPermit.UpdatedTime, 0)

	// Time.Since uses Time.Now() to determine the current time to a fine degree of precision. Here we are checking the
	// time since a specific Unix timestamp, which is a value that is effectively truncated to the nearest second.
	// Thus, the result of this calculation should also be truncated down to the nearest second since that's all the
	// precision we have. This also makes the log statements look cleaner since it won't display an excessive amount
	// of (meaningless) precision.
	timeSinceLastUpdate := time.Since(timeOfLastUpdate).Truncate(time.Second)

	if currentPermit.CurrentHolder == s.instanceID {
		if timeSinceLastUpdate < t.interval {
			s.logger.Debug("It's currently my duty to run this task but it's not time for it to run.",
				log.WithTaskID(t.id), log.WithTimeSinceLastUpdate(timeSinceLastUpdate),
				log.WithTaskMonitorInterval(t.interval))

			return false, nil
		}

		s.logger.Debug("It's currently my duty to run task.", log.WithTaskID(t.id),
			log.WithTimeSinceLastUpdate(timeSinceLastUpdate))

		return true, nil
	}

	// The idea here is to only take away the task running responsibilities from the current permit holder if it's
	// been an unusually long time since the current permit holder has performed a successful run. If that happens
	// then it indicates that the other Orb server with the permit is down, so someone else needs to grab the permit
	// and take over the duty of running scheduled tasks. Note that the assumption here is that all Orb servers
	// within the cluster have the same interval setting (which they should).
	// So, "unusually long time" means that the 'last update' time is greater than the Task Manager check interval plus
	// the task's run interval, in which case we'll assume that the other instance is dead and will take over.
	maxTime := s.interval + t.interval

	if timeSinceLastUpdate > maxTime {
		s.logger.Info("The current permit holder for this task has not updated the permit in an "+
			"unusually long time. This indicates "+
			"that the permit holder may be down or not responding. I will take over and grab the permit.",
			log.WithPermitHolder(currentPermit.CurrentHolder), log.WithTaskID(t.id),
			log.WithTimeSinceLastUpdate(timeSinceLastUpdate), log.WithMaxTime(maxTime))

		return true, nil
	}

	s.logger.Debug("I will not run this task since I am not the permit holder and ran it recently.",
		log.WithTaskID(t.id), log.WithPermitHolder(currentPermit.CurrentHolder),
		log.WithTimeSinceLastUpdate(timeSinceLastUpdate))

	return false, nil
}

func (s *Manager) updatePermit(taskID string, status status) error {
	s.logger.Debug("Updating the permit for task with current time and status.",
		log.WithTaskID(taskID), log.WithStatus(status))

	p := permit{
		TaskID:        taskID,
		CurrentHolder: s.instanceID,
		Status:        status,
		UpdatedTime:   time.Now().Unix(),
	}

	permitBytes, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal permit: %w", err)
	}

	err = s.coordinationStore.Put(getPermitKey(taskID), permitBytes)
	if err != nil {
		return fmt.Errorf("failed to store permit: %w", err)
	}

	s.logger.Debug("Permit successfully updated for task.", log.WithTaskID(taskID), log.WithStatus(status))

	return nil
}

func getPermitKey(taskID string) string {
	return coordinationPermitKey + "_" + taskID
}

type registration struct {
	handle   func()
	running  uint32
	id       string
	interval time.Duration
}

func (r *registration) run() {
	if !atomic.CompareAndSwapUint32(&r.running, 0, 1) {
		// Already running.
		return
	}

	r.handle()

	atomic.StoreUint32(&r.running, 0)
}

func (r *registration) isRunning() bool {
	return atomic.LoadUint32(&r.running) == 1
}
