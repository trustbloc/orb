/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"context"
	"errors"
	"fmt"
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
)

const logModule = "activity_sync"

var logger = log.New(logModule)

const (
	defaultInterval       = time.Minute
	defaultMinActivityAge = time.Minute

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
	RegisterTask(taskType string, interval time.Duration, task func())
}

// Config contains configuration parameters for the anchor event synchronization task.
type Config struct {
	ServiceIRI     *url.URL
	Interval       time.Duration
	MinActivityAge time.Duration
}

type task struct {
	serviceIRI       *url.URL
	apClient         activityPubClient
	store            *syncStore
	getHandler       func() spi.InboxHandler
	activityPubStore store.Store
	closed           chan struct{}
	minActivityAge   time.Duration
	tracer           trace.Tracer
}

// Register registers the anchor event synchronization task.
func Register(cfg Config, taskMgr taskManager, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler,
) error {
	interval := cfg.Interval

	if interval == 0 {
		interval = defaultInterval
	}

	minActivityAge := cfg.MinActivityAge

	if minActivityAge == 0 {
		minActivityAge = defaultMinActivityAge
	}

	t, err := newTask(cfg.ServiceIRI, apClient, apStore, storageProvider, minActivityAge, handlerFactory)
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}

	logger.Info("Registering activity-sync task.",
		logfields.WithServiceIRI(cfg.ServiceIRI), logfields.WithTaskMonitorInterval(interval),
		logfields.WithMinAge(minActivityAge))

	taskMgr.RegisterTask(taskName, interval, t.run)

	return nil
}

func newTask(serviceIRI *url.URL, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, minActivityAge time.Duration,
	handlerFactory func() spi.InboxHandler,
) (*task, error) {
	s, err := newSyncStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create new run store: %w", err)
	}

	return &task{
		serviceIRI:       serviceIRI,
		apClient:         apClient,
		store:            s,
		activityPubStore: apStore,
		getHandler:       handlerFactory,
		minActivityAge:   minActivityAge,
		closed:           make(chan struct{}),
		tracer:           tracing.Tracer(tracing.SubsystemActivityPub),
	}, nil
}

func (m *task) run() {
	followers, err := m.getServices(store.Follower)
	if err != nil {
		logger.Error("Error retrieving my followers list", log.WithError(err))

		return
	}

	if len(followers) > 0 {
		for _, serviceIRI := range followers {
			err = m.sync(serviceIRI, inbox, func(a *vocab.ActivityType) bool {
				// Only sync Create activities that were originated by this service.
				return a.Type().Is(vocab.TypeCreate) && a.Actor().String() == m.serviceIRI.String()
			})
			if err != nil {
				logger.Warn("Error processing activities from inbox of service",
					logfields.WithServiceIRI(serviceIRI), log.WithError(err))
			}
		}

		logger.Debug("Done synchronizing activities with services that are following me.",
			logfields.WithTotal(len(followers)))
	}

	following, err := m.getServices(store.Following)
	if err != nil {
		logger.Error("Error retrieving my following list", log.WithError(err))

		return
	}

	if len(following) > 0 {
		for _, serviceIRI := range following {
			err = m.sync(serviceIRI, outbox, func(a *vocab.ActivityType) bool {
				return a.Type().IsAny(vocab.TypeCreate, vocab.TypeAnnounce)
			})
			if err != nil {
				logger.Warn("Error processing activities from outbox of service",
					logfields.WithServiceIRI(serviceIRI), log.WithError(err))
			}
		}

		logger.Debug("Done synchronizing activities with services that I'm following.", logfields.WithTotal(len(following)))
	}
}

//nolint:cyclop
func (m *task) sync(serviceIRI *url.URL, src activitySource, shouldSync func(*vocab.ActivityType) bool) error {
	it, lastSyncedPage, lastSyncedIndex, err := m.getNewActivities(serviceIRI, src)
	if err != nil {
		return fmt.Errorf("get new activities: %w", err)
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

			return fmt.Errorf("next activity: %w", e)
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
			return fmt.Errorf("sync activity [%s]: %w", a.ID(), e)
		}

		numProcessed += n

		progress.Log(n, page, currentPage)

		page, index = currentPage, it.NextIndex()-1
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
			return fmt.Errorf("update last synced page [%s] at index [%d]: %w", page, index, err)
		}
	} else {
		logger.Debug("Processed missing anchor events ending at page/index.",
			logfields.WithSource(string(src)), logfields.WithServiceIRI(serviceIRI), logfields.WithTotal(numProcessed),
			logfields.WithURL(page), logfields.WithIndex(index))
	}

	return nil
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
