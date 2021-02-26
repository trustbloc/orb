/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"sync/atomic"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

var logger = log.New("activitypub_service")

// Lifecycle implements the lifecycle of a service, i.e. Start and Stop.
type Lifecycle struct {
	name  string
	state uint32
	start func()
	stop  func()
}

// New returns a new Lifecycle.
func New(name string, start, stop func()) *Lifecycle {
	return &Lifecycle{
		name:  name,
		start: start,
		stop:  stop,
	}
}

// Start starts the service.
func (h *Lifecycle) Start() {
	if !atomic.CompareAndSwapUint32(&h.state, spi.StateNotStarted, spi.StateStarting) {
		logger.Debugf("[%s] Service already started", h.name)

		return
	}

	logger.Debugf("[%s] Starting service ...", h.name)

	h.start()

	logger.Debugf("[%s] ... service started", h.name)

	atomic.StoreUint32(&h.state, spi.StateStarted)
}

// Stop stops the service.
func (h *Lifecycle) Stop() {
	if !atomic.CompareAndSwapUint32(&h.state, spi.StateStarted, spi.StateStopped) {
		logger.Debugf("[%s] Service already stopped", h.name)

		return
	}

	logger.Debugf("[%s] Stopping service ...", h.name)

	h.stop()

	logger.Debugf("[%s] ... service stopped", h.name)
}

// State returns the state of the service.
func (h *Lifecycle) State() spi.State {
	return atomic.LoadUint32(&h.state)
}
