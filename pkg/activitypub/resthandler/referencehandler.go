/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// NewFollowers returns a new 'followers' REST handler that retrieves a service's list of followers.
func NewFollowers(cfg *Config, activityStore spi.Store, verifier signatureVerifier, tm authTokenManager) *Reference {
	return NewReference(FollowersPath, spi.Follower, spi.SortAscending, false, cfg, activityStore,
		getObjectIRI(cfg.ObjectIRI), getID("followers"), verifier, tm)
}

// NewFollowing returns a new 'following' REST handler that retrieves a service's list of following.
func NewFollowing(cfg *Config, activityStore spi.Store, verifier signatureVerifier, tm authTokenManager) *Reference {
	return NewReference(FollowingPath, spi.Following, spi.SortAscending, false, cfg, activityStore,
		getObjectIRI(cfg.ObjectIRI), getID("following"), verifier, tm)
}

// NewWitnesses returns a new 'witnesses' REST handler that retrieves a service's list of witnesses.
func NewWitnesses(cfg *Config, activityStore spi.Store, verifier signatureVerifier, tm authTokenManager) *Reference {
	return NewReference(WitnessesPath, spi.Witness, spi.SortAscending, false, cfg, activityStore,
		getObjectIRI(cfg.ObjectIRI), getID("witnesses"), verifier, tm)
}

// NewWitnessing returns a new 'witnessing' REST handler that retrieves collection of the services that the
// local service is witnessing.
func NewWitnessing(cfg *Config, activityStore spi.Store, verifier signatureVerifier, tm authTokenManager) *Reference {
	return NewReference(WitnessingPath, spi.Witnessing, spi.SortAscending, false, cfg, activityStore,
		getObjectIRI(cfg.ObjectIRI), getID("witnessing"), verifier, tm)
}

// NewLiked returns a new 'liked' REST handler that retrieves the references of all the anchor events that
// this service liked.
func NewLiked(cfg *Config, activityStore spi.Store, verifier signatureVerifier, tm authTokenManager) *Reference {
	return NewReference(LikedPath, spi.Liked, spi.SortAscending, true, cfg, activityStore,
		getObjectIRI(cfg.ObjectIRI), getID("liked"), verifier, tm)
}

type createCollectionFunc func(items []*vocab.ObjectProperty, opts ...vocab.Opt) interface{}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// Reference implements a REST handler that retrieves references as a collection of IRIs.
type Reference struct {
	*handler

	refType              spi.ReferenceType
	createCollection     createCollectionFunc
	createCollectionPage createCollectionFunc
	getID                getIDFunc
	getObjectIRI         getObjectIRIFunc
}

// NewReference returns a new reference REST handler.
func NewReference(path string, refType spi.ReferenceType, sortOrder spi.SortOrder, ordered bool,
	cfg *Config, activityStore spi.Store, getObjectIRI getObjectIRIFunc, getID getIDFunc,
	verifier signatureVerifier, tm authTokenManager) *Reference {
	h := &Reference{
		refType:              refType,
		createCollection:     createCollection(ordered),
		createCollectionPage: createCollectionPage(ordered),
		getID:                getID,
		getObjectIRI:         getObjectIRI,
	}

	h.handler = newHandler(path, cfg, activityStore, h.handle, verifier, sortOrder, tm)

	return h
}

func (h *Reference) handle(w http.ResponseWriter, req *http.Request) {
	ok, _, err := h.Authorize(req)
	if err != nil {
		logger.Errorf("[%s] Error authorizing request: %s", h.endpoint, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	if !ok {
		h.writeResponse(w, http.StatusUnauthorized, []byte(unauthorizedResponse))

		return
	}

	objectIRI, err := h.getObjectIRI(req)
	if err != nil {
		logger.Errorf("[%s] Error getting object IRI: %s", h.endpoint, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	id, err := h.getID(objectIRI, req)
	if err != nil {
		logger.Errorf("[%s] Error generating ID: %s", h.endpoint, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	if h.isPaging(req) {
		h.handleReferencePage(w, req, objectIRI, id)
	} else {
		h.handleReference(w, objectIRI, id)
	}
}

func (h *Reference) handleReference(w http.ResponseWriter, objectIRI, id *url.URL) {
	coll, err := h.getReference(objectIRI, id)
	if err != nil {
		logger.Errorf("[%s] Error retrieving %s for object IRI [%s]: %s",
			h.endpoint, h.refType, objectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	collBytes, err := h.marshal(coll)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal %s collection for object IRI [%s]: %s",
			h.endpoint, h.refType, objectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.writeResponse(w, http.StatusOK, collBytes)
}

func (h *Reference) handleReferencePage(w http.ResponseWriter, req *http.Request, objectIRI, id *url.URL) {
	var page interface{}

	var err error

	pageNum, ok := h.getPageNum(req)
	if ok {
		page, err = h.getPage(objectIRI, id,
			spi.WithPageSize(h.PageSize), spi.WithPageNum(pageNum), spi.WithSortOrder(h.sortOrder))
	} else {
		page, err = h.getPage(objectIRI, id,
			spi.WithPageSize(h.PageSize), spi.WithSortOrder(h.sortOrder))
	}

	if err != nil {
		logger.Errorf("[%s] Error retrieving page for object IRI [%s]: %s",
			h.endpoint, objectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	pageBytes, err := h.marshal(page)
	if err != nil {
		logger.Errorf("[%s] Unable to marshal page for object IRI [%s]: %s",
			h.endpoint, objectIRI, err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.writeResponse(w, http.StatusOK, pageBytes)
}

func (h *Reference) getReference(objectIRI, id *url.URL) (interface{}, error) {
	it, err := h.activityStore.QueryReferences(h.refType,
		spi.NewCriteria(
			spi.WithObjectIRI(objectIRI),
		),
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	firstURL, err := h.getPageURL(id, -1)
	if err != nil {
		return nil, err
	}

	totalItems, err := it.TotalItems()
	if err != nil {
		return nil, fmt.Errorf("failed to get total items from reference query: %w", err)
	}

	lastURL, err := h.getPageURL(id, getLastPageNum(totalItems, h.PageSize, h.sortOrder))
	if err != nil {
		return nil, err
	}

	return h.createCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithFirst(firstURL),
		vocab.WithLast(lastURL),
		vocab.WithTotalItems(totalItems),
	), nil
}

func (h *Reference) getPage(objectIRI, id *url.URL, opts ...spi.QueryOpt) (interface{}, error) {
	it, err := h.activityStore.QueryReferences(
		h.refType,
		spi.NewCriteria(spi.WithObjectIRI(objectIRI)),
		opts...,
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = it.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	options := storeutil.GetQueryOptions(opts...)

	refs, err := storeutil.ReadReferences(it, options.PageSize)
	if err != nil {
		return nil, err
	}

	items := make([]*vocab.ObjectProperty, len(refs))

	for i, ref := range refs {
		items[i] = vocab.NewObjectProperty(vocab.WithIRI(ref))
	}

	totalItems, err := it.TotalItems()
	if err != nil {
		return nil, fmt.Errorf("failed to get total items from reference query: %w", err)
	}

	id, prev, next, err := h.getIDPrevNextURL(id, totalItems, options)
	if err != nil {
		return nil, err
	}

	return h.createCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPrev(prev),
		vocab.WithNext(next),
		vocab.WithTotalItems(totalItems),
	), nil
}

func createCollection(ordered bool) createCollectionFunc {
	if ordered {
		return func(items []*vocab.ObjectProperty, opts ...vocab.Opt) interface{} {
			return vocab.NewOrderedCollection(items, opts...)
		}
	}

	return func(items []*vocab.ObjectProperty, opts ...vocab.Opt) interface{} {
		return vocab.NewCollection(items, opts...)
	}
}

func createCollectionPage(ordered bool) createCollectionFunc {
	if ordered {
		return func(items []*vocab.ObjectProperty, opts ...vocab.Opt) interface{} {
			return vocab.NewOrderedCollectionPage(items, opts...)
		}
	}

	return func(items []*vocab.ObjectProperty, opts ...vocab.Opt) interface{} {
		return vocab.NewCollectionPage(items, opts...)
	}
}
