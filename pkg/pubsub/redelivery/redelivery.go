/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redelivery

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.New("pubsub")

const (
	metadataRedeliveryAttempts = "redelivery_attempts"

	defaultMaxRetries     = 5
	defaultInitialBackoff = 100 * time.Millisecond
	defaultMaxBackoff     = time.Second
	defaultBackoffFactor  = 1.5
	defaultMaxMessages    = 20
)

type entry struct {
	msg   *message.Message
	delay time.Duration
}

// Config holds the configuration parameters for the redelivery service.
type Config struct {
	// MaxRetries is maximum number of times a retry will be attempted.
	MaxRetries int

	// InitialBackoff is the first interval between retries. Subsequent intervals will be scaled by BackoffFactor.
	InitialBackoff time.Duration

	// MaxBackoff sets the limit for the exponential backoff of retries. The interval will not be
	// increased beyond MaxBackoff.
	MaxBackoff time.Duration

	// BackoffFactor is the factor by which the waiting interval will be multiplied between retries.
	BackoffFactor float64

	// MaxMessages is the maximum number of messages that can be concurrently managed by the redelivery service.
	MaxMessages int
}

// DefaultConfig returns the default configuration parameters for the redelivery service.
func DefaultConfig() *Config {
	return &Config{
		MaxRetries:     defaultMaxRetries,
		InitialBackoff: defaultInitialBackoff,
		MaxBackoff:     defaultMaxBackoff,
		BackoffFactor:  defaultBackoffFactor,
		MaxMessages:    defaultMaxMessages,
	}
}

// Service manages redelivery of messages that failed delivery. The messages are published after a delay which is
// calculated according to the provided config, which includes an initial backoff and a backoff factor.
type Service struct {
	*Config
	*lifecycle.Lifecycle

	serviceName string
	notifyChan  chan<- *message.Message
	entryChan   chan *entry
	done        chan struct{}
	wg          sync.WaitGroup
}

// NewService returns a new redelivery service.
func NewService(serviceName string, cfg *Config, notifyChan chan<- *message.Message) *Service {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Service{
		serviceName: serviceName,
		Config:      cfg,
		notifyChan:  notifyChan,
		entryChan:   make(chan *entry, cfg.MaxMessages),
		done:        make(chan struct{}),
	}

	m.Lifecycle = lifecycle.New(serviceName+"-redelivery",
		lifecycle.WithStart(m.start),
		lifecycle.WithStop(m.stop),
	)

	return m
}

// Add adds a message for redelivery. The time when the redelivery attempt will occur is returned, or an error
// is returned if the message cannot be redelivered. This function generally returns immediately, although if
// the number of messages already being redelivered has reached the MaxMessages limit then this function will
// block until a previously added message has been processed.
func (m *Service) Add(msg *message.Message) (time.Time, error) {
	if m.State() != lifecycle.StateStarted {
		return time.Time{}, lifecycle.ErrNotStarted
	}

	redeliveryAttempts := 0

	redeliverAttemptsStr, ok := msg.Metadata[metadataRedeliveryAttempts]
	if ok {
		ra, err := strconv.Atoi(redeliverAttemptsStr)
		if err != nil {
			return time.Time{},
				fmt.Errorf("convert redelivery attempts metadata to number for message [%s]: %w", msg.UUID, err)
		}

		redeliveryAttempts = ra
	}

	if redeliveryAttempts >= m.MaxRetries {
		return time.Time{}, fmt.Errorf("unable to redeliver message after %d redelivery attempts", redeliveryAttempts)
	}

	newMsg := msg.Copy()

	newMsg.Metadata[metadataRedeliveryAttempts] = strconv.Itoa(redeliveryAttempts + 1)

	backoff := m.backoff(redeliveryAttempts)

	m.entryChan <- &entry{
		msg:   newMsg,
		delay: backoff,
	}

	logger.Debugf("[%s] Adding message for redelivery: ID [%s], Delay [%s], Redelivery Attempts: %d",
		m.serviceName, msg.UUID, backoff, redeliveryAttempts)

	return time.Now().Add(backoff), nil
}

func (m *Service) start() {
	logger.Infof("[%s] Redelivery service started.", m.serviceName)

	go m.monitor()
}

func (m *Service) stop() {
	m.done <- struct{}{}

	logger.Debugf("[%s] Waiting for monitor to stop ...", m.serviceName)

	<-m.done

	logger.Infof("[%s] Redelivery service stopped", m.serviceName)
}

func (m *Service) monitor() {
	for {
		select {
		case entry := <-m.entryChan:
			m.wg.Add(1)

			go m.redeliver(entry)

		case <-m.done:
			logger.Debugf("[%s] Waiting for all tasks to complete ...", m.serviceName)

			m.wg.Wait()

			m.done <- struct{}{}

			logger.Debugf("[%s] ... monitor has stopped", m.serviceName)

			return
		}
	}
}

func (m *Service) redeliver(entry *entry) {
	logger.Debugf("[%s] Waiting %s to redeliver message %s", m.serviceName, entry.delay, entry.msg.UUID)

	<-time.After(entry.delay)

	logger.Debugf("[%s] Submitting message %s after waiting %s ...",
		m.serviceName, entry.msg.UUID, entry.delay)

	m.notifyChan <- entry.msg

	logger.Debugf("[%s] ... submitted message %s after waiting %s",
		m.serviceName, entry.msg.UUID, entry.delay)

	m.wg.Done()
}

func (m *Service) backoff(retries int) time.Duration {
	backoff, max := float64(m.InitialBackoff), float64(m.MaxBackoff)

	for i := 0; i < retries && backoff < max; i++ {
		backoff *= m.BackoffFactor
	}

	if backoff > max {
		backoff = max
	}

	return time.Duration(backoff)
}
