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

	"github.com/trustbloc/orb/internal/pkg/log"
	apstore "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

var logger = log.NewStructured("nodeinfo")

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

	done                    chan struct{}
	interval                time.Duration
	serviceIRI              *url.URL
	apStore                 apstore.Store
	stats                   *stats
	mutex                   sync.RWMutex
	multipleTagQueryCapable bool
}

// NewService returns a new NodeInfo service.
// If this Orb server uses a storage provider that can do queries using 2 tags, then we can take advantage of a
// feature in the underlying Aries storage provider to update the stats more efficiently.
// If logger is nil, then a default will be used.
func NewService(serviceIRI *url.URL, refreshInterval time.Duration, apStore apstore.Store,
	multipleTagQueryCapable bool) *Service {
	r := &Service{
		apStore:                 apStore,
		serviceIRI:              serviceIRI,
		done:                    make(chan struct{}),
		interval:                refreshInterval,
		stats:                   &stats{},
		multipleTagQueryCapable: multipleTagQueryCapable,
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

	logger.Info("Started NodeInfo service")
}

func (r *Service) stop() {
	close(r.done)

	logger.Info("Stopped NodeInfo service")
}

func (r *Service) refresh() {
	for {
		select {
		case <-time.After(r.interval):
			if err := r.retrieve(); err != nil {
				logger.Warn("Error updating stats", log.WithError(err))
			}
		case <-r.done:
			logger.Debug("Exiting stats retriever.")

			return
		}
	}
}

// TODO (#979): Support updating stats using multi-tag queries for all storage types so we can avoid loading too much
// in memory.
func (r *Service) retrieve() error {
	if !r.multipleTagQueryCapable {
		return r.updateStatsUsingSingleTagQuery()
	}

	return r.updateStatsUsingMultiTagQuery()
}

func (r *Service) updateStatsUsingSingleTagQuery() error {
	it, err := r.apStore.QueryActivities(
		apstore.NewCriteria(
			apstore.WithReferenceType(apstore.Outbox),
			apstore.WithObjectIRI(r.serviceIRI),
		),
	)
	if err != nil {
		return fmt.Errorf("query ActivityPub outbox: %w", err)
	}

	defer func() {
		err = it.Close()
		if err != nil {
			log.CloseIteratorError(logger, err)
		}
	}()

	s := &stats{}

	for {
		ref, err := it.Next()
		if err != nil {
			if errors.Is(err, apstore.ErrNotFound) {
				break
			}

			return fmt.Errorf("query ActivityPub outbox: %w", err)
		}

		switch {
		case ref.Type().Is(vocab.TypeCreate):
			atomic.AddUint64(&s.Posts, 1)
		case ref.Type().Is(vocab.TypeLike):
			atomic.AddUint64(&s.Comments, 1)
		}
	}

	logger.Debug("Updated stats", log.WithData([]byte(s.String())))

	r.mutex.Lock()

	r.stats = s

	r.mutex.Unlock()

	return nil
}

func (r *Service) updateStatsUsingMultiTagQuery() error {
	totalCreateActivities, totalLikeActivities, err := r.getTotalActivityCounts()
	if err != nil {
		return fmt.Errorf("get total activity counts: %w", err)
	}

	r.updateStatsStruct(totalCreateActivities, totalLikeActivities)

	return nil
}

func (r *Service) getTotalActivityCounts() (int, int, error) {
	totalCreateActivities, err := r.getTotalActivityCount(vocab.TypeCreate)
	if err != nil {
		return -1, -1, err
	}

	totalLikeActivities, err := r.getTotalActivityCount(vocab.TypeLike)
	if err != nil {
		return -1, -1, err
	}

	return totalCreateActivities, totalLikeActivities, nil
}

func (r *Service) getTotalActivityCount(activityType vocab.Type) (int, error) {
	it, err := r.apStore.QueryReferences(apstore.Outbox,
		apstore.NewCriteria(
			apstore.WithObjectIRI(r.serviceIRI),
			apstore.WithType(activityType),
		),
	)
	if err != nil {
		return -1, fmt.Errorf("query ActivityPub outbox for %s activities: %w", activityType, err)
	}

	totalCreateActivities, err := it.TotalItems()
	if err != nil {
		return -1, fmt.Errorf("get total items from reference iterator after querying"+
			" ActivityPub outbox for %s activities: %w", activityType, err)
	}

	return totalCreateActivities, nil
}

func (r *Service) updateStatsStruct(totalCreateActivities, totalLikeActivities int) {
	r.mutex.Lock()

	r.stats = &stats{
		Posts:    uint64(totalCreateActivities),
		Comments: uint64(totalLikeActivities),
	}

	r.mutex.Unlock()
}
