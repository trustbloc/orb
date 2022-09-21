/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

// ActivityPubClient reads ActivityPub actors and collections from the service endpoint.
type ActivityPubClient struct {
	cmd          *cobra.Command
	sendRequest  requestSender
	overridesMap map[string]string
}

// NewActivityPubClient returns a new ActivityPub client.
func NewActivityPubClient(cmd *cobra.Command) (*ActivityPubClient, error) {
	httpClient, err := NewHTTPClient(cmd)
	if err != nil {
		return nil, err
	}

	headers := newAuthTokenHeader(cmd)

	overridesMap := make(map[string]string)

	const mappingParts = 2

	for _, mapping := range cmdutil.GetUserSetOptionalVarFromArrayString(cmd, TargetOverrideFlagName,
		TargetOverrideEnvKey) {
		pair := strings.Split(mapping, "->")
		if len(pair) != mappingParts {
			return nil, fmt.Errorf("invalid target override %s", mapping)
		}

		overridesMap[pair[0]] = pair[1]
	}

	return &ActivityPubClient{
		cmd:          cmd,
		overridesMap: overridesMap,
		sendRequest: func(req []byte, method, endpointURL string) ([]byte, error) {
			return SendRequest(httpClient, req, headers, method, endpointURL)
		},
	}, nil
}

// ResolveActor returns the actor for the given endpoint.
func (c *ActivityPubClient) ResolveActor(actorEndpoint string) (*vocab.ActorType, error) {
	resp, err := c.sendRequest(nil, http.MethodGet, c.overrideTarget(actorEndpoint))
	if err != nil {
		return nil, fmt.Errorf("send http request: %w", err)
	}

	actor := &vocab.ActorType{}

	if err := json.Unmarshal(resp, actor); err != nil {
		return nil, fmt.Errorf("unmarshal actor: %w", err)
	}

	return actor, nil
}

// GetCollection returns an ActivityPub collection iterator for the given collection IRI.
func (c *ActivityPubClient) GetCollection(collURI *url.URL) (*ActivityPubCollectionIterator, error) {
	return newAPCollIterator(c.cmd, collURI.String(), c.sendRequest, c.overrideTarget)
}

// CollectionContains returns true if the given ActivityPub collection contains the given IRI.
func (c *ActivityPubClient) CollectionContains(collURI *url.URL, iri string) (bool, error) {
	it, err := c.GetCollection(collURI)
	if err != nil {
		return false, fmt.Errorf("get ActivityPub collection iterator: %w", err)
	}

	for {
		item, err := it.Next()
		if err != nil {
			if errors.Is(err, orberrors.ErrContentNotFound) {
				return false, nil
			}

			return false, err
		}

		if item.String() == iri {
			return true, nil
		}
	}
}

// overrideTarget checks if there is an override for the given target (specified with the --target-override flag).
// If so, a new target URL is returned, otherwise the same target is returned.
func (c *ActivityPubClient) overrideTarget(targetURI string) string {
	for oldTarget, newTarget := range c.overridesMap {
		if strings.Contains(targetURI, "//"+oldTarget) {
			return strings.Replace(targetURI, "//"+oldTarget, "//"+newTarget, 1)
		}
	}

	return targetURI
}

// ActivityPubCollectionIterator iterates over an ActivityPub collection.
type ActivityPubCollectionIterator struct {
	cmd               *cobra.Command
	sendRequest       requestSender
	getTargetOverride targetOverrideFunc
	nextPage          *url.URL
	items             []*vocab.ObjectProperty
	index             int
}

type requestSender func(req []byte, method, endpointURL string) ([]byte, error)

type targetOverrideFunc func(targetURI string) string

func newAPCollIterator(cmd *cobra.Command, collURI string, sendRequest requestSender,
	getTargetOverride targetOverrideFunc) (*ActivityPubCollectionIterator, error) {
	resp, err := sendRequest(nil, http.MethodGet, getTargetOverride(collURI))
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %w", err)
	}

	coll := &vocab.CollectionType{}

	if err := json.Unmarshal(resp, coll); err != nil {
		return nil, err
	}

	return &ActivityPubCollectionIterator{
		cmd:               cmd,
		sendRequest:       sendRequest,
		getTargetOverride: getTargetOverride,
		nextPage:          coll.First(),
	}, nil
}

// Next returns the next item in the collection.
func (it *ActivityPubCollectionIterator) Next() (*url.URL, error) {
	if it.index >= len(it.items) {
		if it.nextPage == nil {
			return nil, orberrors.ErrContentNotFound
		}

		resp, err := it.sendRequest(nil, http.MethodGet, it.getTargetOverride(it.nextPage.String()))
		if err != nil {
			return nil, fmt.Errorf("send http request: %w", err)
		}

		collPage := &vocab.CollectionPageType{}

		if err := json.Unmarshal(resp, collPage); err != nil {
			return nil, err
		}

		it.items = collPage.Items()
		it.index = 0
		it.nextPage = collPage.Next()
	}

	i := it.index

	it.index++

	if i >= len(it.items) {
		return nil, orberrors.ErrContentNotFound
	}

	return it.items[i].IRI(), nil
}
