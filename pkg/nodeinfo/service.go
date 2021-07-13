/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"

	apstore "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.New("nodeinfo")

type stats struct {
	Posts    uint64
	Comments uint64
}

func (s *stats) String() string {
	return fmt.Sprintf("Posts: %d, Comments: %d", s.Posts, s.Comments)
}

// Service periodically polls various Orb services and produces NodeInfo data.
type Service struct {
	*lifecycle.Lifecycle

	done       chan struct{}
	interval   time.Duration
	serviceIRI *url.URL
	apStore    apstore.Store
	stats      *stats
	mutex      sync.RWMutex
}

// NewService returns a new NodeInfo service.
func NewService(apStore apstore.Store, serviceIRI *url.URL, refreshInterval time.Duration) *Service {
	r := &Service{
		apStore:    apStore,
		serviceIRI: serviceIRI,
		done:       make(chan struct{}),
		interval:   refreshInterval,
		stats:      &stats{},
	}

	r.Lifecycle = lifecycle.New("nodeinfo",
		lifecycle.WithStart(r.start),
		lifecycle.WithStop(r.stop))

	return r
}

// GetNodeInfo returns a NodeInfo struct compatible with the given version.
func (r *Service) GetNodeInfo(version Version) *NodeInfo {
	var repository string

	if version == V2_1 {
		repository = orbRepository
	}

	r.mutex.RLock()

	stats := r.stats

	r.mutex.RUnlock()

	return &NodeInfo{
		Version:   version,
		Protocols: []string{activityPubProtocol},
		Software: Software{
			Name:       "Orb",
			Version:    OrbVersion,
			Repository: repository,
		},
		Services: Services{
			Inbound:  []string{},
			Outbound: []string{},
		},
		OpenRegistrations: false,
		Usage: Usage{
			Users: Users{
				Total: 1,
			},
			LocalPosts:    int(stats.Posts),
			LocalComments: int(stats.Comments),
		},
	}
}

func (r *Service) start() {
	go r.refresh()

	logger.Infof("Started NodeInfo service")
}

func (r *Service) stop() {
	close(r.done)

	logger.Infof("Stopped NodeInfo service")
}

func (r *Service) refresh() {
	for {
		select {
		case <-time.After(r.interval):
			r.retrieve()
		case <-r.done:
			logger.Debugf("Exiting stats retriever.")

			return
		}
	}
}

// TODO: This function needs to be refactored to use a tag that contains the activity type so as not to load all of the
// activities from the outbox and process them in memory (issue #577). Changes to Aries storage are required.
func (r *Service) retrieve() {
	it, err := r.apStore.QueryActivities(
		apstore.NewCriteria(
			apstore.WithReferenceType(apstore.Outbox),
			apstore.WithObjectIRI(r.serviceIRI),
		),
	)
	if err != nil {
		logger.Errorf("query ActivityPub outbox: %w", err)

		return
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	s := &stats{}

	for {
		ref, err := it.Next()
		if err != nil {
			if errors.Is(err, apstore.ErrNotFound) {
				break
			}

			logger.Errorf("query ActivityPub outbox: %w", err)

			return
		}

		switch {
		case ref.Type().Is(vocab.TypeCreate):
			atomic.AddUint64(&s.Posts, 1)
		case ref.Type().Is(vocab.TypeLike):
			atomic.AddUint64(&s.Comments, 1)
		}
	}

	logger.Debugf("Updated stats: %s", s)

	r.mutex.Lock()

	r.stats = s

	r.mutex.Unlock()
}
