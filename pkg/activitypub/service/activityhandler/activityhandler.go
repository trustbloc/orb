/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_service")

const (
	defaultBufferSize      = 100
	defaultMaxWitnessDelay = 10 * time.Minute
)

// Config holds the configuration parameters for the activity handler.
type Config struct {
	// ServiceName is the name of the service (used for logging).
	ServiceName string

	// ServiceIRI is the IRI of the local service (actor). It is used as the 'actor' in activities
	// that are posted to the outbox by the handler.
	ServiceIRI *url.URL

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int

	// MaxWitnessDelay is the maximum delay from when the witness receives the transaction (via an Offer) for
	// the witness to include the transaction into the ledger.
	MaxWitnessDelay time.Duration
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
}

type handler struct {
	*Config
	*lifecycle.Lifecycle

	store       store.Store
	mutex       sync.RWMutex
	subscribers []chan *vocab.ActivityType
	client      activityPubClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func newHandler(cfg *Config, s store.Store, httpClient httpClient) *handler {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	if cfg.MaxWitnessDelay == 0 {
		cfg.MaxWitnessDelay = defaultMaxWitnessDelay
	}

	h := &handler{
		Config: cfg,
		store:  s,
		client: client.New(httpClient),
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName, lifecycle.WithStop(h.stop))

	return h
}

func (h *handler) stop() {
	logger.Infof("[%s] Stopping activity handler", h.ServiceName)

	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, ch := range h.subscribers {
		close(ch)
	}

	h.subscribers = nil
}

// Subscribe allows a client to receive published activities.
func (h *handler) Subscribe() <-chan *vocab.ActivityType {
	ch := make(chan *vocab.ActivityType, h.BufferSize)

	h.mutex.Lock()
	h.subscribers = append(h.subscribers, ch)
	h.mutex.Unlock()

	return ch
}

func (h *handler) notify(activity *vocab.ActivityType) {
	h.mutex.RLock()
	subscribers := h.subscribers
	h.mutex.RUnlock()

	for _, ch := range subscribers {
		ch <- activity
	}
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		AnchorCredentialHandler: &noOpAnchorCredentialPublisher{},
		FollowerAuth:            &acceptAllFollowerAuth{},
		ProofHandler:            &noOpProofHandler{},
	}
}

func (h *handler) newActivityID() *url.URL {
	id, err := url.Parse(fmt.Sprintf("%s/%s", h.ServiceIRI.String(), uuid.New()))
	if err != nil {
		// Should never happen since we've already validated the URLs
		panic(err)
	}

	return id
}

func (h *handler) resolveActor(iri *url.URL) (*vocab.ActorType, error) {
	actor, err := h.store.GetActor(iri)
	if err == nil {
		return actor, nil
	}

	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// The actor isn't in our local store. Retrieve the actor from the remote server.
	return h.client.GetActor(iri)
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
			return true
		}
	}

	return false
}
