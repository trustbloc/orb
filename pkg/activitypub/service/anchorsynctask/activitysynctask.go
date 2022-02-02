/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
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
	GetActivities(iri *url.URL, order client.Order) (client.ActivityIterator, error)
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
}

// Register registers the anchor event synchronization task.
func Register(cfg Config, taskMgr taskManager, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler) error {
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

	logger.Infof("Registering activity-sync task - ServiceIRI: %s, Interval: %s, MinActivityAge: %s.",
		cfg.ServiceIRI, interval, minActivityAge)

	taskMgr.RegisterTask(taskName, interval, t.run)

	return nil
}

func newTask(serviceIRI *url.URL, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, minActivityAge time.Duration,
	handlerFactory func() spi.InboxHandler) (*task, error) {
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
	}, nil
}

func (m *task) run() {
	followers, err := m.getServices(store.Follower)
	if err != nil {
		logger.Errorf("Error retrieving my followers list: %s", err)

		return
	}

	if len(followers) > 0 {
		for _, serviceIRI := range followers {
			err = m.sync(serviceIRI, inbox, func(a *vocab.ActivityType) bool {
				// Only sync Create activities that were originated by this service.
				return a.Type().Is(vocab.TypeCreate) && a.Actor().String() == m.serviceIRI.String()
			})
			if err != nil {
				logger.Warnf("Error processing activities from inbox of service [%s]: %s", serviceIRI, err)
			}
		}

		logger.Debugf("Done synchronizing activities with %d services that are following me.", len(followers))
	}

	following, err := m.getServices(store.Following)
	if err != nil {
		logger.Errorf("Error retrieving my following list: %s", err)

		return
	}

	if len(following) > 0 {
		for _, serviceIRI := range following {
			err = m.sync(serviceIRI, outbox, func(a *vocab.ActivityType) bool {
				return a.Type().IsAny(vocab.TypeCreate, vocab.TypeAnnounce)
			})
			if err != nil {
				logger.Warnf("Error processing activities from outbox of service [%s]: %s", serviceIRI, err)
			}
		}

		logger.Debugf("Done synchronizing activities with %d services that I'm following.", len(following))
	}
}

//nolint:gocyclo,cyclop,funlen
func (m *task) sync(serviceIRI *url.URL, src activitySource, shouldSync func(*vocab.ActivityType) bool) error {
	it, lastSyncedPage, lastSyncedIndex, err := m.getNewActivities(serviceIRI, src)
	if err != nil {
		return fmt.Errorf("get new activities: %w", err)
	}

	page, index := lastSyncedPage, lastSyncedIndex

	var numProcessed int

	progress := &progressLogger{}

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
			logger.Debugf("%s sync from [%s]: Ignoring activity [%s] of Type %s",
				src, serviceIRI, a.ID(), a.Type())

			page, index = currentPage, it.NextIndex()-1

			continue
		}

		if publishedTime := a.Published(); publishedTime != nil {
			if activityAge := time.Since(*publishedTime); activityAge < m.minActivityAge {
				logger.Debugf("%s sync from [%s]: Not syncing activity [%s] of Type %s since it was added %s ago"+
					" which is less than the minimum activity age of %s",
					src, serviceIRI, a.ID(), a.Type(), activityAge, m.minActivityAge)

				break
			}
		}

		processed, e := m.syncActivity(serviceIRI, currentPage, a)
		if e != nil {
			return fmt.Errorf("sync activity [%s]: %w", a.ID(), e)
		}

		if processed {
			numProcessed++
		}

		progress.Log(processed, page, currentPage)

		page, index = currentPage, it.NextIndex()-1
	}

	if page.String() != lastSyncedPage.String() || index != lastSyncedIndex {
		logger.Debugf("%s sync from [%s]: Updating last synced page to [%s], index [%d]",
			src, serviceIRI, page, index)

		err = m.store.PutLastSyncedPage(serviceIRI, src, page, index)
		if err != nil {
			return fmt.Errorf("update last synced page [%s] at index [%d]: %w", page, index, err)
		}

		if numProcessed > 0 {
			logger.Infof("%s sync from [%s]: Processed %d missing anchor events ending at page [%s], index [%d]",
				src, serviceIRI, numProcessed, page, index)
		}
	} else {
		logger.Debugf("%s sync from [%s]: Processed %d missing anchor events ending at page [%s], index [%d]",
			src, serviceIRI, numProcessed, page, index)
	}

	return nil
}

func (m *task) syncActivity(serviceIRI, currentPage *url.URL, a *vocab.ActivityType) (bool, error) {
	logger.Debugf("Syncing activity [%s] from current page [%s]", a.ID(), currentPage)

	processed, err := m.isProcessed(a)
	if err != nil {
		return false, fmt.Errorf("isProcessed [%s]: %w", a.ID(), err)
	}

	if processed {
		logger.Debugf("Ignoring activity [%s] of type %s since it has already been processed in page [%s].",
			a.ID(), a.Type(), currentPage)

		return false, nil
	}

	logger.Debugf("Processing activity [%s] of type %s from page [%s].", a.ID(), a.Type(), currentPage)

	if e := m.process(serviceIRI, a); e != nil {
		if errors.Is(e, spi.ErrDuplicateAnchorEvent) {
			logger.Debugf("Ignoring activity [%s] of type %s since it has already been processed in page [%s]. "+
				"Error from handler: %s", a.ID(), a.Type(), currentPage, e)

			return false, nil
		}

		return false, fmt.Errorf("process activity [%s]: %w", a.ID(), e)
	}

	return true, nil
}

func (m *task) process(source *url.URL, a *vocab.ActivityType) error {
	switch {
	case a.Type().Is(vocab.TypeCreate):
		logger.Debugf("Processing create activity [%s]", a.ID())

		if err := m.getHandler().HandleCreateActivity(source, a, false); err != nil {
			return fmt.Errorf("handle create activity [%s]: %w", a.ID(), err)
		}

	case a.Type().Is(vocab.TypeAnnounce):
		logger.Debugf("Processing announce activity [%s]", a.ID())

		if err := m.getHandler().HandleAnnounceActivity(source, a); err != nil {
			return fmt.Errorf("handle announce activity [%s]: %w", a.ID(), err)
		}

	default:
		panic("should not have gotten here")
	}

	// Store the activity so that we don't process it again.
	if err := m.activityPubStore.AddActivity(a); err != nil {
		return fmt.Errorf("store activity: %w", err)
	}

	return nil
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
	*url.URL, int, error) {
	page, index, err := m.getLastSyncedPage(serviceIRI, src)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("get last synced page: %w", err)
	}

	it, err := m.apClient.GetActivities(page, client.Forward)
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

	logger.Debugf("Last synced page not found for service [%s]. Will start at the beginning of the %s.",
		serviceIRI, src)

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

func (l *progressLogger) Log(processed bool, page, currentPage fmt.Stringer) {
	if !log.IsEnabledFor(logModule, log.INFO) {
		return
	}

	if processed {
		l.numProcessedInPage++
	}

	if l.numProcessedInPage > 0 && page.String() != currentPage.String() {
		logger.Infof("Processed %d missing anchor events from outbox page [%s]",
			l.numProcessedInPage, page)

		l.numProcessedInPage = 0
	}
}
