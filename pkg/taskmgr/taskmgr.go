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
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	loggerModule          = "task-manager"
	coordinationPermitKey = "task-permit"
	defaultCheckInterval  = 10 * time.Second
)

type logger interface {
	Debugf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
}

type status = string

const (
	statusIdle    status = "idle"
	statusRunning status = "running"
)

// permit is used as an entry within the coordination store to ensure that only one Orb instance
// within a cluster has the duty of running tasks periodically.
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
	logger            logger
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

	s := &Manager{
		interval:          interval,
		done:              make(chan struct{}),
		logger:            log.New(loggerModule),
		coordinationStore: coordinationStore,
		instanceID:        uuid.New().String(),
		tasks:             make(map[string]*registration),
	}

	s.Lifecycle = lifecycle.New("task-manager",
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop))

	return s
}

// RegisterTask registers a task to be periodically run at the given interval. A task is considered to have been
// running too long if the run time exceeds the given maxRunTime, at which point another server instance may take
// over the duty of running tasks.
func (s *Manager) RegisterTask(id string, interval, maxRunTime time.Duration, task func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.tasks[id] = &registration{
		handle:     task,
		id:         id,
		interval:   interval,
		maxRunTime: maxRunTime,
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
		s.logger.Infof("Started task manager.")

		for {
			select {
			case <-time.After(s.interval):
				for _, t := range s.getTasks() {
					s.run(t)
				}
			case <-s.done:
				s.logger.Debugf("Stopped task manager.")

				return
			}
		}
	}()
}

func (s *Manager) stop() {
	close(s.done)
}

func (s *Manager) run(t *registration) {
	if t.isRunning() {
		s.logger.Debugf("Task is already running [%s]", t.id)

		return
	}

	ok, err := s.shouldRun(t)
	if err != nil {
		s.logger.Warnf("An error occurred while checking if task [%s] should run: %s", t.id, err)

		return
	}

	if !ok {
		s.logger.Debugf("Not running task [%s]", t.id)

		return
	}

	err = s.updatePermit(t.id, statusRunning)
	if err != nil {
		s.logger.Errorf("Failed to update permit for task [%s]: %s", t.id, err.Error())

		return
	}

	// Run the task in a new Go routine.

	go func(t *registration) {
		s.logger.Debugf("Running task [%s]", t.id)

		t.run()

		err := s.updatePermit(t.id, statusIdle)
		if err != nil {
			s.logger.Errorf("Failed to update permit: %s", err.Error())
		}

		s.logger.Debugf("Finished running task [%s]", t.id)
	}(t)
}

func (s *Manager) shouldRun(t *registration) (bool, error) {
	currentPermitBytes, err := s.coordinationStore.Get(getPermitKey(t.id))
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			s.logger.Infof("[%s] No existing permit found for task [%s]. I will take on the duty of running the task.",
				s.instanceID, t.id)

			return true, nil
		}

		return false, fmt.Errorf("get permit from DB for task [%s]: %w", t.id, err)
	}

	var currentPermit permit

	err = json.Unmarshal(currentPermitBytes, &currentPermit)
	if err != nil {
		return false, fmt.Errorf("unmarshal permit for task [%s]: %w", t.id, err)
	}

	timeOfLastCleanup := time.Unix(currentPermit.UpdatedTime, 0)

	// Time.Since uses Time.Now() to determine the current time to a fine degree of precision. Here we are checking the
	// time since a specific Unix timestamp, which is a value that is effectively truncated to the nearest second.
	// Thus, the result of this calculation should also be truncated down to the nearest second since that's all the
	// precision we have. This also makes the log statements look cleaner since it won't display an excessive amount
	// of (meaningless) precision.
	timeSinceLastUpdate := time.Since(timeOfLastCleanup).Truncate(time.Second)

	if currentPermit.CurrentHolder == s.instanceID {
		if timeSinceLastUpdate < t.interval {
			s.logger.Debugf("It's currently my duty to run task [%s] but it's not time to run the task since "+
				"I last did this %s ago and the interval for this task is %s.", t.id, timeSinceLastUpdate, t.interval)

			return false, nil
		}

		s.logger.Debugf("It's currently my duty to run task [%s]. I last did this %s ago. I will "+
			"run the task and then update the permit timestamp.", t.id, timeSinceLastUpdate)

		return true, nil
	}

	// The idea here is to only take away the task running responsibilities from the current permit holder if it's
	// been an unusually long time since the current permit holder has performed a successful run. If that happens
	// then it indicates that the other Orb server with the permit is down, so someone else needs to grab the permit
	// and take over the duty of running scheduled tasks. Note that the assumption here is that all Orb servers
	// within the cluster have the same interval setting (which they should).
	if timeSinceLastUpdate > t.maxRunTime {
		s.logger.Infof("The current permit holder (%s) for task [%s] has not performed a run in an "+
			"unusually long time (%s ago which is longer than the configured maximum run time of %s). This indicates "+
			"that %s may be down or not responding. I will take over and grab the permit.",
			currentPermit.CurrentHolder, t.id, timeSinceLastUpdate, t.maxRunTime, currentPermit.CurrentHolder)

		return true, nil
	}

	s.logger.Debugf("I will not run task [%s] since %s currently has the duty and did it recently "+
		"(%s ago).", t.id, currentPermit.CurrentHolder, timeSinceLastUpdate.String())

	return false, nil
}

func (s *Manager) updatePermit(taskID string, status status) error {
	s.logger.Debugf("[%s] Updating the permit for task [%s] with the current time and status [%s].",
		s.instanceID, taskID, status)

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

	s.logger.Debugf("Permit successfully updated for task [%s] with status [%s].", taskID, status)

	return nil
}

func getPermitKey(taskID string) string {
	return coordinationPermitKey + "_" + taskID
}

type registration struct {
	handle     func()
	running    uint32
	id         string
	interval   time.Duration
	maxRunTime time.Duration
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
