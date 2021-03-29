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

func (c *Client) get(iri fmt.Stringer) ([]byte, error) {
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
