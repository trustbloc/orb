/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"net/http"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Outbox implements the 'outbox' REST handler that retrieves a service's outbox.
type Outbox struct {
	*activities
}

// NewOutbox returns a new 'outbox' REST handler.
func NewOutbox(cfg *Config, activityStore spi.Store) *Outbox {
	return &Outbox{
		activities: newActivities(OutboxPath, spi.Outbox, cfg, activityStore),
	}
}

// Inbox implements the 'inbox' REST handler that retrieves a service's inbox.
type Inbox struct {
	*activities
}

// NewInbox returns a new 'inbox' REST handler.
func NewInbox(cfg *Config, activityStore spi.Store) *Outbox {
	return &Outbox{
		activities: newActivities(InboxPath, spi.Inbox, cfg, activityStore),
	}
}

type activities struct {
	*handler

	storeType spi.ActivityStoreType
}

func newActivities(path string, storeType spi.ActivityStoreType, cfg *Config, activityStore spi.Store) *activities {
	h := &activities{
		storeType: storeType,
	}

	h.handler = newHandler(path, cfg, activityStore, h.handle, pageParam, pageNumParam)

	return h
}

func (h *activities) handle(w http.ResponseWriter, req *http.Request) {
	if h.isPaging(req) {
		h.handleActivitiesPage(w, req)
	} else {
		h.handleActivities(w, req)
	}
}

//nolint:dupl
func (h *activities) handleActivities(rw http.ResponseWriter, _ *http.Request) {
	activities, err := h.getActivities()
	if err != nil {
		logger.Errorf("[%s] Error retrieving %s for service IRI [%s]: %s",
			h.endpoint, h.storeType, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	activitiesCollBytes, err := h.marshal(activities)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal %s collection for service IRI [%s]: %s",
			h.endpoint, h.storeType, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, activitiesCollBytes)
}

func (h *activities) handleActivitiesPage(rw http.ResponseWriter, req *http.Request) {
	var page *vocab.OrderedCollectionPageType

	var err error

	pageNum, ok := h.getPageNum(req)
	if ok {
		page, err = h.getPage(
			spi.WithPageSize(h.PageSize),
			spi.WithPageNum(pageNum),
			spi.WithSortOrder(spi.SortDescending),
		)
	} else {
		page, err = h.getPage(
			spi.WithPageSize(h.PageSize),
			spi.WithSortOrder(spi.SortDescending),
		)
	}

	if err != nil {
		logger.Errorf("[%s] Error retrieving page for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	pageBytes, err := h.marshal(page)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal page for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, pageBytes)
}

func (h *activities) getActivities() (*vocab.OrderedCollectionType, error) {
	it, err := h.activityStore.QueryActivities(h.storeType, spi.NewCriteria())
	if err != nil {
		return nil, err
	}

	defer it.Close()

	firstURL, err := h.getPageURL(-1)
	if err != nil {
		return nil, err
	}

	lastURL, err := h.getPageURL(getLastPageNum(it.TotalItems(), h.PageSize, spi.SortDescending))
	if err != nil {
		return nil, err
	}

	return vocab.NewOrderedCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(h.id),
		vocab.WithFirst(firstURL),
		vocab.WithLast(lastURL),
		vocab.WithTotalItems(it.TotalItems()),
	), nil
}

//nolint:dupl
func (h *activities) getPage(opts ...spi.QueryOpt) (*vocab.OrderedCollectionPageType, error) {
	it, err := h.activityStore.QueryActivities(h.storeType, spi.NewCriteria(spi.WithActorIRI(h.ServiceIRI)), opts...)
	if err != nil {
		return nil, err
	}

	defer it.Close()

	options := storeutil.GetQueryOptions(opts...)

	activities, err := storeutil.ReadActivities(it, options.PageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*vocab.ObjectProperty, len(activities))

	for i, activity := range activities {
		items[i] = vocab.NewObjectProperty(vocab.WithActivity(activity))
	}

	id, prev, next, err := h.getIDPrevNextURL(it.TotalItems(), options)
	if err != nil {
		return nil, err
	}

	return vocab.NewOrderedCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPrev(prev),
		vocab.WithNext(next),
		vocab.WithTotalItems(it.TotalItems()),
	), nil
}
