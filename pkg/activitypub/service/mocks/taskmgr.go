/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"
	"time"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

// TaskManager is a mock implementation of a task manager.
type TaskManager struct {
	*lifecycle.Lifecycle

	instanceID string
	tasks      []*task
	mutex      sync.RWMutex
	interval   time.Duration
	done       chan struct{}
}

// NewTaskManager returns a new mock task manager.
func NewTaskManager(instanceID string) *TaskManager {
	m := &TaskManager{
		instanceID: instanceID,
		interval:   time.Second,
		done:       make(chan struct{}),
	}

	m.Lifecycle = lifecycle.New("task-manager",
		lifecycle.WithStart(m.start),
		lifecycle.WithStop(m.stop),
	)

	return m
}

// WithInterval sets the check interval.
func (m *TaskManager) WithInterval(interval time.Duration) *TaskManager {
	m.interval = interval

	return m
}

// Start starts a Go routine to run the registered tasks.
func (m *TaskManager) start() {
	ticker := time.NewTicker(m.interval)

	go func() {
		for {
			select {
			case <-m.done:
				return

			case <-ticker.C:
				m.mutex.RLock()

				for _, task := range m.tasks {
					task.start()
				}

				m.mutex.RUnlock()
			}
		}
	}()
}

// Stop stops the running Go routine.
func (m *TaskManager) stop() {
	close(m.done)
}

type task struct {
	interval    time.Duration
	run         func()
	lastRunTime time.Time
}

func (t *task) start() {
	if t.lastRunTime.IsZero() || time.Since(t.lastRunTime) >= t.interval {
		t.run()

		t.lastRunTime = time.Now()
	}
}

// InstanceID returns the server instance ID.
func (m *TaskManager) InstanceID() string {
	return m.instanceID
}

// RegisterTask registers the given task to be run at the given interval.
func (m *TaskManager) RegisterTask(_ string, interval time.Duration, run func()) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.tasks = append(m.tasks, &task{
		interval: interval,
		run:      run,
	})
}
