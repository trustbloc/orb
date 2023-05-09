/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	store2 "github.com/trustbloc/orb/pkg/store"
)

const logModule = "activity_sync"

var logger = log.New(logModule)

const (
	defaultInterval            = time.Minute
	defaultAcceleratedInterval = 15 * time.Second
	defaultMinActivityAge      = time.Minute
	defaultMaxActivitiesToSync = math.MaxInt

	taskName = "activity-sync"
)

type activitySource string

const (
	inbox  activitySource = "Inbox"
	outbox activitySource = "Outbox"
)

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
	GetActivities(ctx context.Context, iri *url.URL, order client.Order) (client.ActivityIterator, error)
}

type taskManager interface {
	RegisterTaskEx(taskType string, interval time.Duration, task func() time.Duration)
}

// Config contains configuration parameters for the anchor event synchronization task.
type Config struct {
	ServiceIRI          *url.URL
	Interval            time.Duration
	AcceleratedInterval time.Duration
	MinActivityAge      time.Duration
	MaxActivitiesToSync int
}

type task struct {
	serviceIRI          *url.URL
	apClient            activityPubClient
	store               *syncStore
	getHandler          func() spi.InboxHandler
	activityPubStore    store.Store
	closed              chan struct{}
	minActivityAge      time.Duration
	maxActivitiesToSync int
	acceleratedInterval time.Duration
	tracer              trace.Tracer
}

// Register registers the anchor event synchronization task.
func Register(cfg Config, taskMgr taskManager, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler,
) error {
	config := resolveConfig(&cfg)

	t, err := newTask(config, apClient, apStore, storageProvider, handlerFactory)
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}

	logger.Info("Registering activity-sync task.",
		logfields.WithServiceIRI(config.ServiceIRI), logfields.WithTaskMonitorInterval(config.Interval),
		logfields.WithMinAge(config.MinActivityAge), logfields.WithMaxActivitiesToSync(config.MaxActivitiesToSync))

	taskMgr.RegisterTaskEx(taskName, config.Interval, t.run)

	return nil
}

func newTask(cfg *Config, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler,
) (*task, error) {
	s, err := newSyncStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create new run store: %w", err)
	}

	return &task{
		serviceIRI:          cfg.ServiceIRI,
		apClient:            apClient,
		store:               s,
		activityPubStore:    apStore,
		getHandler:          handlerFactory,
		minActivityAge:      cfg.MinActivityAge,
		maxActivitiesToSync: cfg.MaxActivitiesToSync,
		acceleratedInterval: cfg.AcceleratedInterval,
		closed:              make(chan struct{}),
		tracer:              tracing.Tracer(tracing.SubsystemActivityPub),
	}, nil
}

func (m *task) run() time.Duration {
	numFromFollowers, err := m.syncFollowers(m.maxActivitiesToSync)
	if err != nil {
		logger.Error("Error synchronizing activities", log.WithError(err))

		return 0
	}

	var numFromFollowing int

	if numFromFollowers < m.maxActivitiesToSync {
		numFromFollowing, err = m.syncFollowing(m.maxActivitiesToSync - numFromFollowers)
		if err != nil {
			logger.Error("Error synchronizing activities", log.WithError(err))

			return 0
		}
	}

	numTotal := numFromFollowers + numFromFollowing

	if numTotal > 0 {
		if numTotal >= m.maxActivitiesToSync {
			logger.Info("Reached the maximum number of activities to sync. Will continue syncing in the next run.",
				logfields.WithNumActivitiesSynced(numTotal), logfields.WithNextActivitySyncInterval(m.acceleratedInterval))

			return m.acceleratedInterval
		}

		logger.Info("Done synchronizing activities", logfields.WithNumActivitiesSynced(numTotal))
	}

	return 0
}

func (m *task) syncFollowers(maxActivitiesToSync int) (int, error) {
	followers, err := m.getServices(store.Follower)
	if err != nil {
		logger.Error("Error retrieving my followers list", log.WithError(err))

		return 0, err
	}

	if len(followers) == 0 {
		return 0, nil
	}

	var numProcessed int

	for _, serviceIRI := range followers {
		num, err := m.sync(serviceIRI, inbox, maxActivitiesToSync-numProcessed, func(a *vocab.ActivityType) bool {
			// Only sync Create activities that were originated by this service.
			return a.Type().Is(vocab.TypeCreate) && a.Actor().String() == m.serviceIRI.String()
		})
		if err != nil {
			logger.Warn("Error processing activities from inbox of service",
				logfields.WithServiceIRI(serviceIRI), log.WithError(err))
		} else {
			numProcessed += num

			if numProcessed >= maxActivitiesToSync {
				break
			}
		}
	}

	logger.Debug("Done synchronizing activities with services that are following me.", logfields.WithTotal(len(followers)),
		logfields.WithNumActivitiesSynced(numProcessed))

	return numProcessed, nil
}

func (m *task) syncFollowing(maxActivitiesToSync int) (int, error) {
	following, err := m.getServices(store.Following)
	if err != nil {
		return 0, fmt.Errorf("retrieve following list: %w", err)
	}

	if len(following) == 0 {
		return 0, nil
	}

	var numProcessed int

	for _, serviceIRI := range following {
		num, err := m.sync(serviceIRI, outbox, maxActivitiesToSync-numProcessed, func(a *vocab.ActivityType) bool {
			return a.Type().IsAny(vocab.TypeCreate, vocab.TypeAnnounce)
		})
		if err != nil {
			logger.Warn("Error processing activities from outbox of service",
				logfields.WithServiceIRI(serviceIRI), log.WithError(err))
		} else {
			numProcessed += num

			if numProcessed >= maxActivitiesToSync {
				break
			}
		}
	}

	logger.Debug("Done synchronizing activities with services that I'm following.", logfields.WithTotal(len(following)),
		logfields.WithNumActivitiesSynced(numProcessed))

	return numProcessed, nil
}

//nolint:cyclop
func (m *task) sync(serviceIRI *url.URL, src activitySource, maxNumActivitiesToProcess int,
	shouldSync func(*vocab.ActivityType) bool,
) (int, error) {
	it, lastSyncedPage, lastSyncedIndex, err := m.getNewActivities(serviceIRI, src)
	if err != nil {
		return 0, fmt.Errorf("get new activities: %w", err)
	}

	page, index := lastSyncedPage, lastSyncedIndex

	var numProcessed int

	progress := &progressLogger{}

	span := tracing.NewSpan(m.tracer, context.Background())
	defer span.End()

	for {
		a, e := it.Next()
		if e != nil {
			if errors.Is(e, client.ErrNotFound) {
				break
			}

			return numProcessed, fmt.Errorf("next activity: %w", e)
		}

		currentPage := it.CurrentPage()

		if !shouldSync(a) {
			logger.Debug("Ignoring activity.",
				logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI), logfields.WithActivityID(a.ID()),
				logfields.WithActivityType(a.Type().String()))

			page, index = currentPage, it.NextIndex()-1

			continue
		}

		if publishedTime := a.Published(); publishedTime != nil {
			if activityAge := time.Since(*publishedTime); activityAge < m.minActivityAge {
				logger.Debug("Not syncing activity since it was just added recently.",
					logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI), logfields.WithActivityID(a.ID()),
					logfields.WithActivityType(a.Type().String()), logfields.WithAge(activityAge), logfields.WithMinAge(m.minActivityAge))

				break
			}
		}

		n, e := m.syncActivity(span.Start("sync activities"), serviceIRI, currentPage, a)
		if e != nil {
			return numProcessed, fmt.Errorf("sync activity [%s]: %w", a.ID(), e)
		}

		numProcessed += n

		progress.Log(n, page, currentPage)

		page, index = currentPage, it.NextIndex()-1

		if numProcessed >= maxNumActivitiesToProcess {
			break
		}
	}

	if page.String() != lastSyncedPage.String() || index != lastSyncedIndex {
		if numProcessed > 0 {
			logger.Info("Processed missing anchor events ending at page/index.",
				logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI), logfields.WithTotal(numProcessed),
				logfields.WithURL(page), logfields.WithIndex(index))
		}

		logger.Info("Updating last synced page", logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI),
			logfields.WithURL(page), logfields.WithIndex(index))

		err = m.store.PutLastSyncedPage(serviceIRI, src, page, index)
		if err != nil {
			return numProcessed, fmt.Errorf("update last synced page [%s] at index [%d]: %w", page, index, err)
		}
	} else {
		logger.Debug("Processed missing anchor events ending at page/index.",
			logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI), logfields.WithTotal(numProcessed),
			logfields.WithURL(page), logfields.WithIndex(index))
	}

	return numProcessed, nil
}

func (m *task) syncActivity(ctx context.Context, serviceIRI, currentPage *url.URL, a *vocab.ActivityType) (int, error) {
	logger.Debug("Syncing activity from current page", logfields.WithActivityID(a.ID()), logfields.WithURL(currentPage))

	processed, err := m.isProcessed(a)
	if err != nil {
		return 0, fmt.Errorf("isProcessed [%s]: %w", a.ID(), err)
	}

	if processed {
		logger.Debug("Ignoring activity since it has already been processed.", logfields.WithActivityID(a.ID()),
			logfields.WithActivityType(a.Type().String()), logfields.WithURL(currentPage))

		return 0, nil
	}

	logger.Debug("Processing activity.", logfields.WithActivityID(a.ID()), logfields.WithActivityType(a.Type().String()),
		logfields.WithURL(currentPage))

	numProcessed, e := m.process(ctx, serviceIRI, a)
	if e != nil {
		if errors.Is(e, spi.ErrDuplicateAnchorEvent) {
			logger.Debug("Ignoring activity since it has already been processed.",
				logfields.WithActivityID(a.ID()), logfields.WithActivityType(a.Type().String()),
				logfields.WithURL(currentPage), log.WithError(e))

			return 0, nil
		}

		return 0, fmt.Errorf("process activity [%s]: %w", a.ID(), e)
	}

	return numProcessed, nil
}

func (m *task) process(ctx context.Context, source *url.URL, a *vocab.ActivityType) (numProcessed int, err error) {
	switch {
	case a.Type().Is(vocab.TypeCreate):
		logger.Debug("Processing create activity", logfields.WithActivityID(a.ID()))

		err = m.getHandler().HandleCreateActivity(ctx, source, a, false)
		if err != nil {
			return 0, fmt.Errorf("handle create activity [%s]: %w", a.ID(), err)
		}

		numProcessed = 1

	case a.Type().Is(vocab.TypeAnnounce):
		logger.Debug("Processing announce activity", logfields.WithActivityID(a.ID()))

		numProcessed, err = m.getHandler().HandleAnnounceActivity(ctx, source, a)
		if err != nil {
			return 0, fmt.Errorf("handle announce activity [%s]: %w", a.ID(), err)
		}

	default:
		panic("should not have gotten here")
	}

	// Store the activity so that we don't process it again.
	if err := m.activityPubStore.AddActivity(a); err != nil {
		return 0, fmt.Errorf("store activity: %w", err)
	}

	return numProcessed, nil
}

func (m *task) isProcessed(a *vocab.ActivityType) (bool, error) {
	_, err := m.activityPubStore.GetActivity(a.ID().URL())
	if err == nil {
		return true, nil
	}

	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}

	return false, err
}

func (m *task) getServices(refType store.ReferenceType) ([]*url.URL, error) {
	it, err := m.activityPubStore.QueryReferences(refType, store.NewCriteria(store.WithObjectIRI(m.serviceIRI)))
	if err != nil {
		return nil, fmt.Errorf("error querying for references of type %s from storage: %w", refType, err)
	}

	defer store2.CloseIterator(it)

	refs, err := storeutil.ReadReferences(it, 0)
	if err != nil {
		return nil, fmt.Errorf("error retrieving references of type %s from storage: %w", refType, err)
	}

	return refs, nil
}

func (m *task) getNewActivities(serviceIRI *url.URL, src activitySource) (client.ActivityIterator,
	*url.URL, int, error,
) {
	page, index, err := m.getLastSyncedPage(serviceIRI, src)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("get last synced page: %w", err)
	}

	it, err := m.apClient.GetActivities(context.Background(), page, client.Forward)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("get activities from [%s]: %w", page, err)
	}

	// Set the index to the next activity from the last one processed in the page.
	it.SetNextIndex(index + 1)

	return it, page, index, nil
}

func (m *task) getLastSyncedPage(serviceIRI *url.URL, src activitySource) (*url.URL, int, error) {
	lastSyncedPage, index, err := m.store.GetLastSyncedPage(serviceIRI, src)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, 0, fmt.Errorf("get last synced page for %s: %w", src, err)
		}
	}

	if lastSyncedPage != nil {
		return lastSyncedPage, index, nil
	}

	logger.Debug("Last synced page not found for service. Will start at the beginning.",
		logfields.WithServiceIRI(serviceIRI), logfields.WithSource(string(src)))

	actor, err := m.apClient.GetActor(serviceIRI)
	if err != nil {
		return nil, 0, fmt.Errorf("get actor: %w", err)
	}

	if src == inbox {
		return actor.Inbox(), 0, nil
	}

	return actor.Outbox(), 0, nil
}

func resolveConfig(cfg *Config) *Config {
	config := *cfg

	if config.Interval == 0 {
		config.Interval = defaultInterval
	}

	if config.AcceleratedInterval == 0 {
		config.AcceleratedInterval = defaultAcceleratedInterval
	}

	if config.MinActivityAge == 0 {
		config.MinActivityAge = defaultMinActivityAge
	}

	if config.MaxActivitiesToSync == 0 {
		config.MaxActivitiesToSync = defaultMaxActivitiesToSync
	}

	return &config
}

type progressLogger struct {
	numProcessedInPage int
}

func (l *progressLogger) Log(numProcessed int, page, currentPage fmt.Stringer) {
	if !logger.IsEnabled(log.INFO) {
		return
	}

	l.numProcessedInPage += numProcessed

	if l.numProcessedInPage > 0 && page.String() != currentPage.String() {
		logger.Info("Processed missing anchor events.", logfields.WithTotal(l.numProcessedInPage), logfields.WithURL(page))

		l.numProcessedInPage = 0
	}
}
