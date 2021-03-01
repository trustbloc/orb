/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

const defaultBufferSize = 100

// Config holds the configuration parameters for the activity handler.
type Config struct {
	// ServiceName is the name of the service (used for logging).
	ServiceName string

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int
}

// Handler provides an implementation for the ActivityHandler interface.
type Handler struct {
	*Config
	*lifecycle.Lifecycle
	*service.Handlers

	name        string
	mutex       sync.RWMutex
	subscribers []chan *vocab.ActivityType
}

// New returns a new ActivityPub activity handler.
func New(cfg *Config, opts ...service.HandlerOpt) *Handler {
	options := defaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	h := &Handler{
		Config:   cfg,
		Handlers: options,
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName, lifecycle.WithStop(h.stop))

	return h
}

func (h *Handler) stop() {
	logger.Infof("[%s] Stopping activity handler", h.name)

	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, ch := range h.subscribers {
		close(ch)
	}

	h.subscribers = nil
}

// Subscribe allows a client to receive published activities.
func (h *Handler) Subscribe() <-chan *vocab.ActivityType {
	ch := make(chan *vocab.ActivityType, h.BufferSize)

	h.mutex.Lock()
	h.subscribers = append(h.subscribers, ch)
	h.mutex.Unlock()

	return ch
}

// HandleActivity handles the ActivityPub activity.
func (h *Handler) HandleActivity(activity *vocab.ActivityType) error {
	typeProp := activity.Type()

	switch {
	case typeProp.Is(vocab.TypeCreate):
		return h.handleCreateActivity(activity)
	default:
		return fmt.Errorf("unsupported activity type: %s", typeProp.Types())
	}
}

func (h *Handler) handleCreateActivity(create *vocab.ActivityType) error {
	logger.Debugf("[%s] Handling 'Create' activity: %s", h.name, create.ID())

	// TODO: Announce the 'Create'.

	h.notify(create)

	return nil
}

func (h *Handler) notify(activity *vocab.ActivityType) {
	h.mutex.RLock()
	subscribers := h.subscribers
	h.mutex.RUnlock()

	for _, ch := range subscribers {
		ch <- activity
	}
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{}
}
