/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("activitypub_client")

// ErrNotFound is returned when the object is not found or the iterator has reached the end.
var ErrNotFound = fmt.Errorf("not found")

// ReferenceIterator iterates over all of the references in a result set.
type ReferenceIterator interface {
	Next() (*url.URL, error)
	TotalItems() int
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client implements an ActivityPub client which retrieves ActivityPub objects (such as actors, activities,
// and collections) from remote sources.
type Client struct {
	httpClient httpClient
}

// New returns a new ActivityPub client.
func New(httpClient httpClient) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

// GetActor retrieves the actor at the given IRI.
//nolint:interfacer
func (c *Client) GetActor(actorIRI *url.URL) (*vocab.ActorType, error) {
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

// GetReferences returns an iterator that reads all references at the given IRI. The IRI either resolves
// to an ActivityPub actor, collection or ordered collection.
func (c *Client) GetReferences(iri *url.URL) (ReferenceIterator, error) {
	respBytes, err := c.get(iri)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", iri, err)
	}

	logger.Debugf("Got response from %s: %s", iri, respBytes)

	items, firstPage, totalItems, err := unmarshalReference(respBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarsalling response from %s: %w", iri, err)
	}

	return newIterator(items, firstPage, totalItems, c.get), nil
}

func (c *Client) get(iri *url.URL) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, iri.String(), nil)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create HTTP request")
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", iri, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s returned status code %d", iri, resp.StatusCode)
	}

	defer func() {
		if e := resp.Body.Close(); e != nil {
			logger.Warnf("Error closing response body from %s: %s", iri, e)
		}
	}()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response from %s: %w", iri, err)
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

func newIterator(items []*url.URL, nextPage *url.URL, totalItems int, retrieve getFunc) *referenceIterator {
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
		return fmt.Errorf("request to %s failed: %w", it.nextPage, err)
	}

	logger.Debugf("Got response from %s: %s", it.nextPage, respBytes)

	refs, nextPage, err := unmarshalCollectionPage(respBytes)
	if err != nil {
		return err
	}

	logger.Debugf("Got page %s with %d items. Next page: %s", it.nextPage, len(refs), nextPage)

	it.currentItems = refs
	it.currentIndex = 0
	it.nextPage = nextPage

	return nil
}

func unmarshalReference(respBytes []byte) (items []*url.URL, nextPage *url.URL, totalCount int, err error) {
	obj := &vocab.ObjectType{}

	if err := json.Unmarshal(respBytes, &obj); err != nil {
		return nil, nil, 0, err
	}

	switch {
	case obj.Type().Is(vocab.TypeService):
		actor := &vocab.ActorType{}
		if err := json.Unmarshal(respBytes, actor); err != nil {
			return nil, nil, 0, fmt.Errorf("invalid service in response: %w", err)
		}

		return []*url.URL{actor.ID().URL()}, nil, 1, nil

	case obj.Type().Is(vocab.TypeCollection):
		coll := &vocab.CollectionType{}
		if err := json.Unmarshal(respBytes, coll); err != nil {
			return nil, nil, 0, fmt.Errorf("invalid collection in response: %w", err)
		}

		return nil, coll.First(), coll.TotalItems(), nil

	case obj.Type().Is(vocab.TypeOrderedCollection):
		coll := &vocab.OrderedCollectionType{}
		if err := json.Unmarshal(respBytes, coll); err != nil {
			return nil, nil, 0, fmt.Errorf("invalid ordered collection in response: %w", err)
		}

		return nil, coll.First(), coll.TotalItems(), nil

	default:
		return nil, nil, 0, fmt.Errorf("expecting Service, Collection or OrderedCollection in response payload")
	}
}

func unmarshalCollectionPage(respBytes []byte) ([]*url.URL, *url.URL, error) {
	obj := &vocab.ObjectType{}

	if err := json.Unmarshal(respBytes, &obj); err != nil {
		return nil, nil, err
	}

	var items []*vocab.ObjectProperty

	var next *url.URL

	switch {
	case obj.Type().Is(vocab.TypeCollectionPage):
		coll := &vocab.CollectionPageType{}

		err := json.Unmarshal(respBytes, coll)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid collection page in response: %w", err)
		}

		next = coll.Next()
		items = coll.Items()

	case obj.Type().Is(vocab.TypeOrderedCollectionPage):
		coll := &vocab.OrderedCollectionPageType{}

		err := json.Unmarshal(respBytes, coll)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid ordered collection page in response: %w", err)
		}

		next = coll.Next()
		items = coll.Items()

	default:
		return nil, nil, fmt.Errorf("expecting CollectionPage or OrderedCollectionPage in response payload")
	}

	var refs []*url.URL

	for _, item := range items {
		if item.IRI() != nil {
			logger.Debugf("Adding %s to the recipient list", item.IRI())

			refs = append(refs, item.IRI())
		} else {
			logger.Warnf("expecting IRI item for collection but got %s", item.Type())
		}
	}

	return refs, next, nil
}
