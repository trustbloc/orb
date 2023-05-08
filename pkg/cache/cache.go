/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	defaultRefreshInterval = time.Duration(0) // Refresh is disabled by default.
	defaultRetryBackoff    = 5 * time.Second
	defaultMonitorInterval = 5 * time.Second
	defaultMaxLoadAttempts = math.MaxUint
	defaultCacheName       = "cache"
)

type loader func(key interface{}) (interface{}, error)

type options struct {
	refreshInterval time.Duration
	retryBackoff    time.Duration
	monitorInterval time.Duration
	maxLoadAttempts uint
	name            string
}

// Opt specifies a config retriever option.
type Opt func(opts *options)

// WithRefreshInterval sets the interval at which each entry in the cache is refreshed.
// If set to 0 (default) then the items will not be refreshed.
func WithRefreshInterval(value time.Duration) Opt {
	return func(opts *options) {
		opts.refreshInterval = value
	}
}

// WithRetryBackoff specifies the interval at which an entry in the cache errored out at the
// last attempt is retried.
func WithRetryBackoff(value time.Duration) Opt {
	return func(opts *options) {
		opts.retryBackoff = value
	}
}

// WithMonitorInterval specifies the interval at which entries are checked if they need to be refreshed.
func WithMonitorInterval(value time.Duration) Opt {
	return func(opts *options) {
		opts.monitorInterval = value
	}
}

// WithMaxLoadAttempts specifies the maximum number of attempts to unsuccessfully load an entry before
// it is removed from the cache. (Default is to try forever.)
func WithMaxLoadAttempts(value uint) Opt {
	return func(opts *options) {
		opts.maxLoadAttempts = value
	}
}

// WithName sets the name of the cache. (Used only for logging.)
func WithName(value string) Opt {
	return func(opts *options) {
		opts.name = value
	}
}

// Cache implements a cache that loads an entry upon first access (using the provided loader), caches it,
// and then (if required) periodically refreshes the cache entry according the configured
// refresh interval. While the entry is being refreshed callers are served the old value of the entry. If a
// refresh fails then the old value is served and another refresh is attempted at a later time. Refreshing an
// entry does not cause requests for the entry to be blocked, unless the value of the entry is nil.
type Cache struct {
	*lifecycle.Lifecycle
	*options

	data   map[interface{}]*entry
	mutex  sync.RWMutex
	load   loader
	close  chan struct{}
	wg     sync.WaitGroup
	logger *log.Log
}

// New returns a new retriever.
func New(loader loader, opts ...Opt) *Cache {
	options := &options{
		name:            defaultCacheName,
		refreshInterval: defaultRefreshInterval,
		monitorInterval: defaultMonitorInterval,
		retryBackoff:    defaultRetryBackoff,
		maxLoadAttempts: defaultMaxLoadAttempts,
	}

	for _, opt := range opts {
		opt(options)
	}

	c := &Cache{
		options: options,
		data:    make(map[interface{}]*entry),
		load:    loader,
		close:   make(chan struct{}),
		logger:  log.New(options.name),
	}

	c.Lifecycle = lifecycle.New(options.name, lifecycle.WithStart(c.start), lifecycle.WithStop(c.stop))

	c.logger.Debug("Created cache", logfields.WithCacheRefreshInterval(options.refreshInterval))

	return c
}

func (c *Cache) start() {
	if c.refreshInterval > 0 {
		c.wg.Add(1)

		go c.monitor()
	}
}

func (c *Cache) stop() {
	close(c.close)

	c.wg.Wait()
}

// Get returns the cached value for the given key.
func (c *Cache) Get(key interface{}) (interface{}, error) {
	e, _ := c.getEntry(key)

	value, err := e.Value()
	if err != nil {
		return nil, fmt.Errorf("get value: %w", err)
	}

	return value, nil
}

// MarkAsStale marks the entry such that it should load immediately (or as soon as possible)
// without waiting for the next refresh time.
func (c *Cache) MarkAsStale(key interface{}) {
	if e, found := c.getEntry(key); found {
		e.markAsStale()
	}
}

// getEntry returns an existing entry for the given key or adds a new entry.
// If the entry already exists then true is returned otherwise false if a new entry
// was added.
func (c *Cache) getEntry(key interface{}) (*entry, bool) {
	c.mutex.RLock()
	e, found := c.data[key]
	c.mutex.RUnlock()

	if found {
		return e, true
	}

	c.mutex.Lock()

	e, found = c.data[key]
	if !found {
		// Add the item since it doesn't exist. It will be loaded the next time
		// it's accessed or refreshed.
		e = newEntry(key, c.load, c.refreshInterval, c.retryBackoff)
		c.data[key] = e
	}

	c.mutex.Unlock()

	return e, false
}

func (c *Cache) removeEntry(key interface{}) {
	c.mutex.Lock()
	delete(c.data, key)
	c.mutex.Unlock()
}

func (c *Cache) monitor() {
	ticker := time.NewTicker(c.monitorInterval)
	defer ticker.Stop()

	defer c.wg.Done()

	for {
		select {
		case <-c.close:
			return
		case <-ticker.C:
			c.refresh()
		}
	}
}

func (c *Cache) refresh() {
	entries := c.entries()

	for _, e := range entries {
		if !e.timeToRefresh() {
			continue
		}

		// Delete the entry if it failed to load in the configured maximum number attempts.
		attempts := e.loadAttempts()

		if attempts >= c.maxLoadAttempts {
			c.logger.Debug("Deleting cache entry since it failed to load after the maximum number of attempts",
				logfields.WithKey(fmt.Sprintf("%s", e.key)), logfields.WithCacheRefreshAttempts(int(attempts)))

			c.removeEntry(e.key)
		} else {
			if err := e.load(withLock); err != nil {
				c.logger.Warn("Error refreshing cache entry", log.WithError(err), logfields.WithKey(fmt.Sprintf("%s", e.key)),
					logfields.WithCacheRefreshAttempts(int(e.loadAttempts())))
			} else {
				c.logger.Debug("Successfully refreshed cache entry", logfields.WithKey(fmt.Sprintf("%s", e.key)),
					logfields.WithCacheRefreshAttempts(int(attempts)+1))
			}
		}
	}
}

func (c *Cache) entries() []*entry {
	c.mutex.RLock()

	entries := make([]*entry, len(c.data))

	i := 0
	for _, item := range c.data {
		entries[i] = item
		i++
	}

	c.mutex.RUnlock()

	return entries
}

type entry struct {
	key             interface{}
	value           interface{}
	refreshInterval time.Duration
	retryBackoff    time.Duration
	nextRefreshTime time.Time
	loader          loader
	mutex           sync.RWMutex
	err             error
	attempts        uint
}

func newEntry(key interface{}, loader loader, refreshInterval, retryBackoff time.Duration) *entry {
	return &entry{
		key:             key,
		loader:          loader,
		refreshInterval: refreshInterval,
		retryBackoff:    retryBackoff,
	}
}

func (e *entry) Value() (interface{}, error) {
	e.mutex.RLock()
	value := e.value
	err := e.err
	e.mutex.RUnlock()

	if value != nil {
		return value, nil
	}

	if err != nil {
		// Return the error that was received in the last attempt to load. The error will be cleared
		// at the next successful refresh of the entry. This prevents loading too frequently, potentially
		// causing the server to be overwhelmed.
		return nil, err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.value != nil {
		return e.value, nil
	}

	err = e.load(withNoLock)
	if err != nil {
		e.err = err

		if e.refreshInterval > 0 {
			e.nextRefreshTime = time.Now().Add(e.retryBackoff)
		}

		return nil, err
	}

	return e.value, nil
}

func (e *entry) timeToRefresh() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.nextRefreshTime.Before(time.Now())
}

func (e *entry) loadAttempts() uint {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.attempts
}

// markAsStale sets the time of next refresh to be now (or as soon as possible).
func (e *entry) markAsStale() {
	now := time.Now()

	e.mutex.Lock()
	e.nextRefreshTime = now
	e.mutex.Unlock()
}

type updater func()

type wrapper func(*entry, updater)

func (e *entry) load(wrap wrapper) error {
	v, err := e.loader(e.key)
	if err != nil {
		wrap(e, func() { e.attempts++ })

		return fmt.Errorf("load value: %w", err)
	}

	wrap(e,
		func() {
			e.attempts = 0
			e.value = v
			e.err = nil

			if e.refreshInterval > 0 {
				e.nextRefreshTime = time.Now().Add(e.refreshInterval)
			}
		},
	)

	return nil
}

// withLock locks the entry before calling update.
func withLock(e *entry, update updater) {
	e.mutex.Lock()
	update()
	e.mutex.Unlock()
}

// withNoLock does not lock the entry before calling update.
func withNoLock(_ *entry, update updater) {
	update()
}
