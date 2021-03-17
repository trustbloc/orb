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

// Followers implements the 'followers' REST handler that retrieves a service's list of followers.
type Followers struct {
	*handler
}

// NewFollowers returns a new 'followers' REST handler.
func NewFollowers(cfg *Config, activityStore spi.Store) *Followers {
	h := &Followers{}

	h.handler = newHandler(FollowersPath, cfg, activityStore, h.handle, pageParam, pageNumParam)

	return h
}

func (h *Followers) handle(w http.ResponseWriter, req *http.Request) {
	if h.isPaging(req) {
		h.handleFollowersPage(w, req)
	} else {
		h.handleFollowers(w, req)
	}
}

func (h *Followers) handleFollowers(rw http.ResponseWriter, _ *http.Request) {
	followers, err := h.getFollowers()
	if err != nil {
		logger.Errorf("[%s] Error retrieving followers for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	followersCollBytes, err := h.marshal(followers)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal followers collection for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, followersCollBytes)
}

func (h *Followers) handleFollowersPage(rw http.ResponseWriter, req *http.Request) {
	var page *vocab.CollectionPageType

	var err error

	pageNum, ok := h.getPageNum(req)
	if ok {
		page, err = h.getFollowersPage(spi.WithPageSize(h.PageSize), spi.WithPageNum(pageNum))
	} else {
		page, err = h.getFollowersPage(spi.WithPageSize(h.PageSize))
	}

	if err != nil {
		logger.Errorf("[%s] Error retrieving page for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	pageBytes, err := h.marshal(page)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal followers page for service IRI [%s]: %s",
			h.endpoint, h.ServiceIRI, err)

		h.writeResponse(rw, http.StatusInternalServerError, nil)

		return
	}

	h.writeResponse(rw, http.StatusOK, pageBytes)
}

func (h *Followers) getFollowers() (*vocab.CollectionType, error) {
	it, err := h.activityStore.QueryReferences(spi.Follower,
		spi.NewCriteria(
			spi.WithActorIRI(h.ServiceIRI),
		),
	)
	if err != nil {
		return nil, err
	}

	defer it.Close()

	firstURL, err := h.getPageURL(-1)
	if err != nil {
		return nil, err
	}

	lastURL, err := h.getPageURL(getLastPageNum(it.TotalItems(), h.PageSize, spi.SortAscending))
	if err != nil {
		return nil, err
	}

	return vocab.NewCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(h.id),
		vocab.WithFirst(firstURL),
		vocab.WithLast(lastURL),
		vocab.WithTotalItems(it.TotalItems()),
	), nil
}

func (h *Followers) getFollowersPage(opts ...spi.QueryOpt) (*vocab.CollectionPageType, error) {
	it, err := h.activityStore.QueryReferences(
		spi.Follower,
		spi.NewCriteria(spi.WithActorIRI(h.ServiceIRI)),
		opts...,
	)
	if err != nil {
		return nil, err
	}

	defer it.Close()

	options := storeutil.GetQueryOptions(opts...)

	refs, err := storeutil.ReadReferences(it, options.PageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*vocab.ObjectProperty, len(refs))

	for i, ref := range refs {
		items[i] = vocab.NewObjectProperty(vocab.WithIRI(ref))
	}

	id, prev, next, err := h.getIDPrevNextURL(it.TotalItems(), options)
	if err != nil {
		return nil, err
	}

	return vocab.NewCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPrev(prev),
		vocab.WithNext(next),
		vocab.WithTotalItems(it.TotalItems()),
	), nil
}
