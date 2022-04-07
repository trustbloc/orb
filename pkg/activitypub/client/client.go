/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/bluele/gcache"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("activitypub_client")

const (
	defaultCacheSize       = 100
	defaultCacheExpiration = time.Minute
)

// ErrNotFound is returned when the object is not found or the iterator has reached the end.
var ErrNotFound = fmt.Errorf("not found")

// Order is the order in which activities are returned.
type Order string

const (
	// Forward indicates that activities should be returned in the same order that they were retrieved
	// from the REST endpoint.
	Forward Order = "forward"
	// Reverse indicates that activities should be returned in reverse order that they were retrieved
	// from the REST endpoint..
	Reverse Order = "reverse"
)

// ReferenceIterator iterates over the references in a result set.
type ReferenceIterator interface {
	Next() (*url.URL, error)
	TotalItems() int
}

// ActivityIterator iterates over the activities in a result set.
type ActivityIterator interface {
	// Next returns the next activity or the ErrNotFound error if no more items are available.
	Next() (*vocab.ActivityType, error)
	// NextPage advances to the next page. If there are no more pages then an ErrNotFound error is returned.
	NextPage() (*url.URL, error)
	// SetNextIndex sets the index of the next activity within the current page that Next will return.
	SetNextIndex(int)
	// TotalItems returns the total number of items available at the moment the iterator was created.
	// This value remains constant throughout the lifetime of the iterator.
	TotalItems() int
	// CurrentPage returns the ID of the current page that the iterator is processing.
	CurrentPage() *url.URL
	// NextIndex returns the next index of the current page that will be processed. This function does not
	// advance the iterator.
	NextIndex() int
}

type httpTransport interface {
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

// Config contains configuration parameters for the client.
type Config struct {
	CacheSize       int
	CacheExpiration time.Duration
}

// Client implements an ActivityPub client which retrieves ActivityPub objects (such as actors, activities,
// and collections) from remote sources.
type Client struct {
	httpTransport

	actorCache     gcache.Cache
	publicKeyCache gcache.Cache
}

// New returns a new ActivityPub client.
func New(cfg Config, t httpTransport) *Client {
	c := &Client{
		httpTransport: t,
	}

	cacheSize := cfg.CacheSize

	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}

	cacheExpiration := cfg.CacheExpiration

	if cacheExpiration == 0 {
		cacheExpiration = defaultCacheExpiration
	}

	logger.Debugf("Creating actor cache with size=%d, expiration=%s", cacheSize, cacheExpiration)

	c.actorCache = gcache.New(cacheSize).ARC().
		Expiration(cacheExpiration).
		LoaderFunc(func(i interface{}) (interface{}, error) {
			return c.getActor(i.(*url.URL))
		}).Build()

	c.publicKeyCache = gcache.New(cacheSize).ARC().
		Expiration(cacheExpiration).
		LoaderFunc(func(i interface{}) (interface{}, error) {
			return c.getPublicKey(i.(*url.URL))
		}).Build()

	return c
}

// GetActor retrieves the actor at the given IRI.
//nolint:interfacer
func (c *Client) GetActor(actorIRI *url.URL) (*vocab.ActorType, error) {
	result, err := c.actorCache.Get(actorIRI)
	if err != nil {
		logger.Debugf("Got error retrieving actor from cache for IRI [%s]: %s", actorIRI, err)

		return nil, err
	}

	return result.(*vocab.ActorType), nil
}

func (c *Client) getActor(actorIRI *url.URL) (*vocab.ActorType, error) {
	respBytes, err := c.get(actorIRI)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", actorIRI, err)
	}

	logger.Debugf("Got response from %s: %s", actorIRI, respBytes)

	actor := &vocab.ActorType{}

	err = json.Unmarshal(respBytes, actor)
	if err != nil {
		return nil, fmt.Errorf("invalid actor in response from %s: %w", actorIRI, err)
	}

	return actor, nil
}

// GetPublicKey retrieves the public key at the given IRI.
//nolint:interfacer
func (c *Client) GetPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error) {
	result, err := c.publicKeyCache.Get(keyIRI)
	if err != nil {
		logger.Debugf("Got error retrieving public key from cache for IRI [%s]: %s", keyIRI, err)

		return nil, err
	}

	return result.(*vocab.PublicKeyType), nil
}

func (c *Client) getPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error) {
	respBytes, err := c.get(keyIRI)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", keyIRI, err)
	}

	logger.Debugf("Got response from %s: %s", keyIRI, respBytes)

	pubKey := &vocab.PublicKeyType{}

	err = json.Unmarshal(respBytes, pubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in response from %s: %w", keyIRI, err)
	}

	return pubKey, nil
}

// GetReferences returns an iterator that reads all references at the given IRI. The IRI either resolves
// to an ActivityPub actor, collection or ordered collection.
func (c *Client) GetReferences(iri *url.URL) (ReferenceIterator, error) {
	respBytes, err := c.get(iri)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", iri, err)
	}

	logger.Debugf("Got response from %s: %s", iri, respBytes)

	objProps, firstPage, _, totalItems, err := unmarshalCollection(respBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarsalling response from %s: %w", iri, err)
	}

	items := make([]*url.URL, len(objProps))

	for i, prop := range objProps {
		items[i] = prop.IRI()
	}

	return newReferenceIterator(items, firstPage, totalItems, c.get), nil
}

// GetActivities returns an iterator that reads activities at the given IRI. The IRI may reference a
// Collection, OrderedCollection, CollectionPage, or OrderedCollectionPage.
func (c *Client) GetActivities(iri *url.URL, order Order) (ActivityIterator, error) {
	respBytes, err := c.get(iri)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", iri, err)
	}

	logger.Debugf("Got response from %s: %s", iri, respBytes)

	obj := &vocab.ObjectType{}

	err = json.Unmarshal(respBytes, &obj)
	if err != nil {
		return nil, err
	}

	switch {
	case obj.Type().IsAny(vocab.TypeCollection, vocab.TypeOrderedCollection):
		return c.activityIteratorFromCollection(respBytes, order)
	case obj.Type().IsAny(vocab.TypeCollectionPage, vocab.TypeOrderedCollectionPage):
		return c.activityIteratorFromCollectionPage(respBytes, order)
	default:
		return nil, fmt.Errorf("invalid collection type %s", obj.Type())
	}
}

func (c *Client) activityIteratorFromCollection(collBytes []byte, order Order) (ActivityIterator, error) {
	_, first, last, totalItems, err := unmarshalCollection(collBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarsal collection: %w", err)
	}

	switch order {
	case Forward:
		logger.Debugf("Creating forward activity iterator - next [%s], total [%d]", first, totalItems)

		return newForwardActivityIterator(nil, nil, first, totalItems, c.get), nil
	case Reverse:
		logger.Debugf("Creating reverse activity iterator - next [%s], total [%d]", last, totalItems)

		return newReverseActivityIterator(nil, nil, last, totalItems, c.get), nil
	default:
		return nil, fmt.Errorf("invalid order [%s]", order)
	}
}

func (c *Client) activityIteratorFromCollectionPage(collBytes []byte, order Order) (ActivityIterator, error) {
	page, err := unmarshalCollectionPage(collBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarsal collection page: %w", err)
	}

	activities := make([]*vocab.ActivityType, len(page.items))

	for i, prop := range page.items {
		activities[i] = prop.Activity()
	}

	switch order {
	case Forward:
		logger.Debugf("Creating forward activity iterator - current [%s], items [%d], total [%d]",
			page.current, len(activities), page.totalItems)

		return newForwardActivityIterator(activities, page.current, page.next, page.totalItems, c.get), nil
	case Reverse:
		logger.Debugf("Creating reverse activity iterator - current [%s], items [%d], total [%d]",
			page.current, len(activities), page.totalItems)

		return newReverseActivityIterator(activities, page.current, page.prev, page.totalItems, c.get), nil
	default:
		return nil, fmt.Errorf("invalid order [%s]", order)
	}
}

func (c *Client) get(iri *url.URL) ([]byte, error) {
	resp, err := c.Get(context.Background(), transport.NewRequest(iri,
		transport.WithHeader(transport.AcceptHeader, transport.ActivityStreamsContentType)))
	if err != nil {
		return nil, orberrors.NewTransientf("transient http error: request to %s failed: %w",
			iri, err)
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			logger.Warnf("Error closing response body from %s: %s", iri, e)
		}
	}()

	logger.Debugf("Got response from %s. Status: %d", iri, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, orberrors.NewTransientf("transient http error: status code %d from %s",
				resp.StatusCode, iri)
		}

		return nil, fmt.Errorf("request to %s returned status code %d", iri, resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, orberrors.NewTransientf("transient http error: read response body from %s: %w",
			iri, err)
	}

	return respBytes, nil
}

type getFunc func(iri *url.URL) ([]byte, error)

type referenceIterator struct {
	totalItems   int
	currentItems []*url.URL
	currentIndex int
	nextPage     *url.URL
	get          getFunc
}

func newReferenceIterator(items []*url.URL, nextPage *url.URL, totalItems int, retrieve getFunc) *referenceIterator {
	return &referenceIterator{
		currentItems: items,
		totalItems:   totalItems,
		nextPage:     nextPage,
		get:          retrieve,
		currentIndex: 0,
	}
}

func (it *referenceIterator) Next() (*url.URL, error) {
	if it.currentIndex >= len(it.currentItems) {
		err := it.getNextPage()
		if err != nil {
			return nil, err
		}
	}

	item := it.currentItems[it.currentIndex]

	it.currentIndex++

	return item, nil
}

func (it *referenceIterator) TotalItems() int {
	return it.totalItems
}

func (it *referenceIterator) getNextPage() error {
	if it.nextPage == nil {
		logger.Debugf("No more pages")

		return ErrNotFound
	}

	logger.Debugf("Retrieving next page %s", it.nextPage)

	respBytes, err := it.get(it.nextPage)
	if err != nil {
		return fmt.Errorf("get references from %s: %w", it.nextPage, err)
	}

	logger.Debugf("Got response from %s: %s", it.nextPage, respBytes)

	page, err := unmarshalCollectionPage(respBytes)
	if err != nil {
		return err
	}

	var refs []*url.URL

	for _, item := range page.items {
		if item.IRI() != nil {
			logger.Debugf("Adding %s to the recipient list", item.IRI())

			refs = append(refs, item.IRI())
		} else {
			logger.Warnf("expecting IRI item for collection but got %s", item.Type())
		}
	}

	it.currentItems = refs
	it.currentIndex = 0
	it.nextPage = page.next

	if len(it.currentItems) == 0 {
		return ErrNotFound
	}

	return nil
}

type getNextIRIFunc func(next, prev *url.URL) *url.URL

type appendFunc func(activities []*vocab.ActivityType, activity *vocab.ActivityType) []*vocab.ActivityType

type activityIterator struct {
	currentItems   []*vocab.ActivityType
	currentPage    *url.URL
	nextPage       *url.URL
	totalItems     int
	currentIndex   int
	numProcessed   int
	get            getFunc
	getNext        getNextIRIFunc
	appendActivity appendFunc
}

func newActivityIterator(items []*vocab.ActivityType, currentPage, nextPage *url.URL, totalItems int,
	get getFunc, getNext getNextIRIFunc, appendActivity appendFunc) *activityIterator {
	return &activityIterator{
		currentItems:   items,
		currentPage:    currentPage,
		nextPage:       nextPage,
		totalItems:     totalItems,
		get:            get,
		getNext:        getNext,
		appendActivity: appendActivity,
	}
}

func (it *activityIterator) CurrentPage() *url.URL {
	return it.currentPage
}

func (it *activityIterator) SetNextIndex(index int) {
	it.numProcessed += index - it.currentIndex
	it.currentIndex = index
}

func (it *activityIterator) NextIndex() int {
	return it.currentIndex
}

func (it *activityIterator) NextPage() (*url.URL, error) {
	unprocessedCount := len(it.currentItems) - it.currentIndex

	if err := it.getNextPage(); err != nil {
		if errors.Is(err, ErrNotFound) {
			it.numProcessed += unprocessedCount
		}

		return nil, err
	}

	it.numProcessed += unprocessedCount

	return it.CurrentPage(), nil
}

func (it *activityIterator) Next() (*vocab.ActivityType, error) {
	if it.numProcessed >= it.totalItems {
		// All items were already processed. There may actually be additional items if we retrieve
		// another page (since items keep being added in a running system) but we want to process
		// only the items that were available when the iterator was created.
		return nil, ErrNotFound
	}

	if it.currentIndex >= len(it.currentItems) {
		err := it.getNextPage()
		if err != nil {
			return nil, err
		}
	}

	item := it.currentItems[it.currentIndex]

	it.currentIndex++
	it.numProcessed++

	return item, nil
}

func (it *activityIterator) TotalItems() int {
	return it.totalItems
}

func (it *activityIterator) getNextPage() error {
	if it.nextPage == nil {
		logger.Debugf("No more pages")

		return ErrNotFound
	}

	logger.Debugf("Retrieving next page %s", it.nextPage)

	respBytes, err := it.get(it.nextPage)
	if err != nil {
		return fmt.Errorf("get activities from %s: %w", it.nextPage, err)
	}

	logger.Debugf("Got response from %s: %s", it.nextPage, respBytes)

	page, err := unmarshalCollectionPage(respBytes)
	if err != nil {
		return err
	}

	var activities []*vocab.ActivityType

	for _, item := range page.items {
		if item.Activity() != nil {
			logger.Debugf("Adding activity to the recipient list - ID [%s], Type %s",
				item.Activity().ID(), item.Activity().Type())

			activities = it.appendActivity(activities, item.Activity())
		} else {
			logger.Warnf("expecting activity item for collection but got %s", item.Type())
		}
	}

	it.currentIndex = 0
	it.currentItems = activities
	it.currentPage = page.current
	it.nextPage = it.getNext(page.next, page.prev)

	if len(it.currentItems) == 0 {
		return ErrNotFound
	}

	return nil
}

func newForwardActivityIterator(items []*vocab.ActivityType, currentPage, nextPage *url.URL,
	totalItems int, retrieve getFunc) *activityIterator {
	return newActivityIterator(items, currentPage, nextPage, totalItems, retrieve,
		func(next, _ *url.URL) *url.URL {
			return next
		},
		func(activities []*vocab.ActivityType, activity *vocab.ActivityType) []*vocab.ActivityType {
			return append(activities, activity)
		},
	)
}

func newReverseActivityIterator(items []*vocab.ActivityType, currentPage, nextPage *url.URL,
	totalItems int, retrieve getFunc) *activityIterator {
	return newActivityIterator(reverseSort(items), currentPage, nextPage, totalItems, retrieve,
		func(_, prev *url.URL) *url.URL {
			return prev
		},
		func(activities []*vocab.ActivityType, activity *vocab.ActivityType) []*vocab.ActivityType {
			// Prepend the activity since we're iterating in reverseSort order.
			return append([]*vocab.ActivityType{activity}, activities...)
		},
	)
}

func unmarshalCollection(respBytes []byte) (items []*vocab.ObjectProperty, firstPage, lastPage *url.URL,
	totalCount int, err error) {
	obj := &vocab.ObjectType{}

	if err := json.Unmarshal(respBytes, &obj); err != nil {
		return nil, nil, nil, 0, err
	}

	switch {
	case obj.Type().Is(vocab.TypeService):
		actor := &vocab.ActorType{}
		if err := json.Unmarshal(respBytes, actor); err != nil {
			return nil, nil, nil, 0, fmt.Errorf("invalid service in response: %w", err)
		}

		return []*vocab.ObjectProperty{vocab.NewObjectProperty(vocab.WithIRI(actor.ID().URL()))},
			nil, nil, 1, nil

	case obj.Type().Is(vocab.TypeCollection):
		coll := &vocab.CollectionType{}
		if err := json.Unmarshal(respBytes, coll); err != nil {
			return nil, nil, nil, 0, fmt.Errorf("invalid collection in response: %w", err)
		}

		return nil, coll.First(), coll.Last(), coll.TotalItems(), nil

	case obj.Type().Is(vocab.TypeOrderedCollection):
		coll := &vocab.OrderedCollectionType{}
		if err := json.Unmarshal(respBytes, coll); err != nil {
			return nil, nil, nil, 0,
				fmt.Errorf("invalid ordered collection in response: %w", err)
		}

		return nil, coll.First(), coll.Last(), coll.TotalItems(), nil

	default:
		return nil, nil, nil, 0,
			fmt.Errorf("expecting Service, Collection, OrderedCollection, CollectionPage, " +
				"or OrderedCollectionPage in response payload")
	}
}

type page struct {
	items               []*vocab.ObjectProperty
	current, next, prev *url.URL
	totalItems          int
}

func unmarshalCollectionPage(respBytes []byte) (*page, error) {
	obj := &vocab.ObjectType{}

	if err := json.Unmarshal(respBytes, &obj); err != nil {
		return nil, err
	}

	switch {
	case obj.Type().Is(vocab.TypeCollectionPage):
		coll := &vocab.CollectionPageType{}

		err := json.Unmarshal(respBytes, coll)
		if err != nil {
			return nil, fmt.Errorf("invalid collection page in response: %w", err)
		}

		return &page{
			items:      coll.Items(),
			current:    coll.ID().URL(),
			next:       coll.Next(),
			prev:       coll.Prev(),
			totalItems: coll.TotalItems(),
		}, nil

	case obj.Type().Is(vocab.TypeOrderedCollectionPage):
		coll := &vocab.OrderedCollectionPageType{}

		err := json.Unmarshal(respBytes, coll)
		if err != nil {
			return nil, fmt.Errorf("invalid ordered collection page in response: %w", err)
		}

		return &page{
			items:      coll.Items(),
			current:    coll.ID().URL(),
			next:       coll.Next(),
			prev:       coll.Prev(),
			totalItems: coll.TotalItems(),
		}, nil

	default:
		return nil, fmt.Errorf("expecting CollectionPage or OrderedCollectionPage in response payload")
	}
}

func reverseSort(items []*vocab.ActivityType) []*vocab.ActivityType {
	sort.SliceStable(items,
		func(i, j int) bool {
			return i > j //nolint:gocritic
		},
	)

	return items
}
