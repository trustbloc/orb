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

const logModule = "anchor_sync"

var logger = log.New(logModule)

const (
	defaultInterval   = time.Minute
	defaultMaxRunTime = 90 * time.Second
	taskName          = "activity-sync"
)

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
	GetActivities(iri *url.URL, order client.Order) (client.ActivityIterator, error)
}

type taskManager interface {
	RegisterTask(taskType string, interval, maxRunTime time.Duration, task func())
}

// Config contains configuration parameters for the anchor event synchronization task.
type Config struct {
	ServiceIRI *url.URL
	Interval   time.Duration
	MaxRunTime time.Duration
}

type task struct {
	serviceIRI       *url.URL
	apClient         activityPubClient
	store            *syncStore
	getHandler       func() spi.InboxHandler
	activityPubStore store.Store
	closed           chan struct{}
}

// Register registers the anchor event synchronization task.
func Register(cfg Config, taskMgr taskManager, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler) error {
	t, err := newTask(cfg.ServiceIRI, apClient, apStore, storageProvider, handlerFactory)
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}

	interval, maxRunTime := cfg.Interval, cfg.MaxRunTime

	if interval == 0 {
		interval = defaultInterval
	}

	if maxRunTime == 0 {
		maxRunTime = defaultMaxRunTime
	}

	logger.Infof("Registering activity-sync task - ServiceIRI: %s, Interval: %s, MaxRunTime: %s.",
		cfg.ServiceIRI, interval, maxRunTime)

	taskMgr.RegisterTask(taskName, interval, maxRunTime, t.run)

	return nil
}

func newTask(serviceIRI *url.URL, apClient activityPubClient, apStore store.Store,
	storageProvider storage.Provider, handlerFactory func() spi.InboxHandler) (*task, error) {
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
		closed:           make(chan struct{}),
	}, nil
}

func (m *task) run() {
	following, err := m.getFollowing()
	if err != nil {
		logger.Errorf("Error retrieving my following list: %s", err)

		return
	}

	if len(following) > 0 {
		for _, serviceIRI := range following {
			err = m.syncOutbox(serviceIRI)
			if err != nil {
				logger.Warnf("Error processing activities from outbox of service [%s]: %s", serviceIRI, err)
			}
		}

		logger.Debugf("Done synchronizing activities with %d services that I'm following.", len(following))
	}
}

//nolint:gocyclo,cyclop
func (m *task) syncOutbox(serviceIRI *url.URL) error {
	it, lastSyncedPage, lastSyncedIndex, err := m.getNewActivities(serviceIRI)
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

		processed, e := m.syncActivity(currentPage, a)
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
		logger.Debugf("Updating last synced page to [%s], index [%d]", page, index)

		err = m.store.PutLastSyncedPage(serviceIRI, page, index)
		if err != nil {
			return fmt.Errorf("update last synced page [%s] at index [%d]: %w", page, index, err)
		}

		if numProcessed > 0 {
			logger.Infof("Processed %d missing anchor events from outbox ending at page [%s], index [%d]",
				numProcessed, page, index)
		}
	}

	return nil
}

func (m *task) syncActivity(currentPage *url.URL, a *vocab.ActivityType) (bool, error) {
	logger.Debugf("Syncing activity [%s] from current page [%s]", a.ID(), currentPage)

	if !a.Type().IsAny(vocab.TypeCreate, vocab.TypeAnnounce) {
		logger.Debugf("Ignoring activity [%s] of Type %s", a.ID(), a.Type())

		return false, nil
	}

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

	if e := m.process(a); e != nil {
		if errors.Is(e, spi.ErrDuplicateAnchorEvent) {
			logger.Debugf("Ignoring activity [%s] of type %s since it has already been processed in page [%s]. "+
				"Error from handler: %s", a.ID(), a.Type(), currentPage, e)

			return false, nil
		}

		return false, fmt.Errorf("process activity [%s]: %w", a.ID(), e)
	}

	return true, nil
}

func (m *task) process(a *vocab.ActivityType) error {
	switch {
	case a.Type().Is(vocab.TypeCreate):
		logger.Debugf("Processing create activity [%s]", a.ID())

		if err := m.getHandler().HandleCreateActivity(a, false); err != nil {
			return fmt.Errorf("handle create activity [%s]: %w", a.ID(), err)
		}

	case a.Type().Is(vocab.TypeAnnounce):
		logger.Debugf("Processing announce activity [%s]", a.ID())

		if err := m.getHandler().HandleAnnounceActivity(a); err != nil {
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

func (m *task) getFollowing() ([]*url.URL, error) {
	it, err := m.activityPubStore.QueryReferences(store.Following, store.NewCriteria(store.WithObjectIRI(m.serviceIRI)))
	if err != nil {
		return nil, fmt.Errorf("error querying for references of type %s from storage: %w",
			store.Following, err)
	}

	refs, err := storeutil.ReadReferences(it, 0)
	if err != nil {
		return nil, fmt.Errorf("error retrieving references of type %s from storage: %w",
			store.Following, err)
	}

	return refs, nil
}

func (m *task) getNewActivities(serviceIRI *url.URL) (client.ActivityIterator, *url.URL, int, error) {
	page, index, err := m.getLastSyncedPage(serviceIRI)
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

func (m *task) getLastSyncedPage(serviceIRI *url.URL) (*url.URL, int, error) {
	lastSyncedPage, index, err := m.store.GetLastSyncedPage(serviceIRI)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, 0, fmt.Errorf("get last synced page: %w", err)
		}
	}

	if lastSyncedPage != nil {
		return lastSyncedPage, index, nil
	}

	logger.Debugf("Last synced page not found for service [%s]. Will start at the beginning of the outbox.",
		serviceIRI)

	actor, err := m.apClient.GetActor(serviceIRI)
	if err != nil {
		return nil, 0, fmt.Errorf("get actor: %w", err)
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
