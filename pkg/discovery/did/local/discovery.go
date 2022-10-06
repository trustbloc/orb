/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/document/util"
)

var logger = log.New("local-discovery")

type didPublisher interface {
	PublishDID(dids string) error
}

type endpointClient interface {
	GetEndpointFromAnchorOrigin(did string) (*models.Endpoint, error)
}

// New creates new local discovery.
func New(namespace string, didPublisher didPublisher, client endpointClient) *Discovery {
	return &Discovery{
		namespace:      namespace,
		publisher:      didPublisher,
		endpointClient: client,
	}
}

// Discovery implements local did discovery.
type Discovery struct {
	namespace      string
	publisher      didPublisher
	endpointClient endpointClient
}

// RequestDiscovery requests did discovery.
func (d *Discovery) RequestDiscovery(did string) error {
	suffix, err := util.GetSuffix(did)
	if err != nil {
		return err
	}

	latestCID, err := d.discoverLatestCID(did)
	if err != nil {
		logger.Warn("Failed to discover latest CID for DID", log.WithDID(did), log.WithError(err))

		latestCID, err = d.getCID(did, suffix)
		if err != nil {
			return err
		}
	}

	return d.publisher.PublishDID(latestCID + docutil.NamespaceDelimiter + suffix)
}

func (d *Discovery) getCID(id, suffix string) (string, error) {
	parts := strings.Split(id, docutil.NamespaceDelimiter)

	// cid is always second last (an exception is hashlink with metadata)
	cid := parts[len(parts)-2]

	if len(parts) == util.MinOrbIdentifierParts {
		// canonical id
		return cid, nil
	}

	hlOrHint, err := util.BetweenStrings(id, d.namespace+docutil.NamespaceDelimiter, docutil.NamespaceDelimiter+suffix)
	if err != nil {
		return "", fmt.Errorf("failed to get value between namespace and suffix: %w", err)
	}

	return hlOrHint, nil
}

func (d *Discovery) discoverLatestCID(did string) (string, error) {
	endpoint, err := d.endpointClient.GetEndpointFromAnchorOrigin(did)
	if err != nil {
		return "", fmt.Errorf("failed to get endpoints: %w", err)
	}

	logger.Debug("Discovered latest CID for DID", log.WithDID(did), log.WithAnchorOriginEndpoint(endpoint))

	return endpoint.AnchorURI, nil
}
