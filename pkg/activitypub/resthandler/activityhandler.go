/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"net/http"
	"net/url"

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
		activities: newActivities(OutboxPath, spi.Outbox, cfg, activityStore,
			getObjectIRI(cfg.ObjectIRI), getID("outbox"),
		),
	}
}

// Inbox implements the 'inbox' REST handler that retrieves a service's inbox.
type Inbox struct {
	*activities
}

// NewInbox returns a new 'inbox' REST handler.
func NewInbox(cfg *Config, activityStore spi.Store) *Outbox {
	return &Outbox{
		activities: newActivities(InboxPath, spi.Inbox, cfg, activityStore,
			getObjectIRI(cfg.ObjectIRI), getID("inbox"),
		),
	}
}

type getIDFunc func(objectIRI *url.URL) (*url.URL, error)

type getObjectIRIFunc func(req *http.Request) (*url.URL, error)

type activities struct {
	*handler

	refType      spi.ReferenceType
	getID        getIDFunc
	getObjectIRI getObjectIRIFunc
}

func newActivities(path string, refType spi.ReferenceType, cfg *Config, activityStore spi.Store,
	getObjectIRI getObjectIRIFunc, getID getIDFunc) *activities {
	h := &activities{
		refType:      refType,
		getID:        getID,
		getObjectIRI: getObjectIRI,
	}

	h.handler = newHandler(path, cfg, activityStore, h.handle, pageParam, pageNumParam)

	return h
}

func (h *activities) handle(w http.ResponseWriter, req *http.Request) {
	objectIRI, err := h.getObjectIRI(req)
	if err != nil {
		logger.Errorf("[%s] Error getting ObjectIRI: %s", h.endpoint, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	id, err := h.getID(objectIRI)
	if err != nil {
		logger.Errorf("[%s] Error generating ID: %s", h.endpoint, err)

		h.writeResponse(w, http.StatusInternalServerError, nil)

		return
	}

	if h.isPaging(req) {
		h.handleActivitiesPage(w, req, objectIRI, id)
	} else {
		h.handleActivities(w, req, objectIRI, id)
	}
}

//nolint:dupl
func (h *activities) handleActivities(rw http.ResponseWriter, _ *http.Request, objectIRI, id *url.URL) {
	activities, err := h.getActivities(objectIRI, id)
	if err != nil {
		logger.Errorf("[%s] Error retrieving %s for object IRI [%s]: %s",
			h.endpoint, h.refType, objectIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	activitiesCollBytes, err := h.marshal(activities)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal %s collection for object IRI [%s]: %s",
			h.endpoint, h.refType, objectIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, activitiesCollBytes)
}

func (h *activities) handleActivitiesPage(rw http.ResponseWriter, req *http.Request, objectIRI, id *url.URL) {
	var page *vocab.OrderedCollectionPageType

	var err error

	pageNum, ok := h.getPageNum(req)
	if ok {
		page, err = h.getPage(objectIRI, id,
			spi.WithPageSize(h.PageSize),
			spi.WithPageNum(pageNum),
			spi.WithSortOrder(spi.SortDescending),
		)
	} else {
		page, err = h.getPage(objectIRI, id,
			spi.WithPageSize(h.PageSize),
			spi.WithSortOrder(spi.SortDescending),
		)
	}

	if err != nil {
		logger.Errorf("[%s] Error retrieving page for object IRI [%s]: %s",
			h.endpoint, objectIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	pageBytes, err := h.marshal(page)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal page for object IRI [%s]: %s",
			h.endpoint, objectIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, pageBytes)
}

//nolint:dupl
func (h *activities) getActivities(objectIRI, id *url.URL) (*vocab.OrderedCollectionType, error) {
	it, err := h.activityStore.QueryReferences(h.refType,
		spi.NewCriteria(
			spi.WithObjectIRI(objectIRI),
		),
	)
	if err != nil {
		return nil, err
	}

	defer it.Close()

	firstURL, err := h.getPageURL(id, -1)
	if err != nil {
		return nil, err
	}

	lastURL, err := h.getPageURL(id, getLastPageNum(it.TotalItems(), h.PageSize, spi.SortDescending))
	if err != nil {
		return nil, err
	}

	return vocab.NewOrderedCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithFirst(firstURL),
		vocab.WithLast(lastURL),
		vocab.WithTotalItems(it.TotalItems()),
	), nil
}

//nolint:dupl
func (h *activities) getPage(objectIRI, id *url.URL, opts ...spi.QueryOpt) (*vocab.OrderedCollectionPageType, error) {
	it, err := h.activityStore.QueryActivities(
		spi.NewCriteria(
			spi.WithReferenceType(h.refType),
			spi.WithObjectIRI(objectIRI),
		), opts...,
	)
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

	id, prev, next, err := h.getIDPrevNextURL(id, it.TotalItems(), options)
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
