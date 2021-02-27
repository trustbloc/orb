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

type options struct {
	start func()
	stop  func()
}

// Lifecycle implements the lifecycle of a service, i.e. Start and Stop.
type Lifecycle struct {
	*options
	name  string
	state uint32
}

// Opt sets a Lifecycle option.
type Opt func(opts *options)

// WithStart sets the start function which is invoked when Start() is called.
func WithStart(start func()) Opt {
	return func(opts *options) {
		opts.start = start
	}
}

// WithStop sets the stop function which is invoked when Stop() is called.
func WithStop(stop func()) Opt {
	return func(opts *options) {
		opts.stop = stop
	}
}

// New returns a new Lifecycle.
func New(name string, opts ...Opt) *Lifecycle {
	options := &options{
		start: func() {},
		stop:  func() {},
	}

	for _, opt := range opts {
		opt(options)
	}

	return &Lifecycle{
		options: options,
		name:    name,
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
