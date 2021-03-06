/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"fmt"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
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
	suffix, err := d.getSuffix(did)
	if err != nil {
		return err
	}

	latestCID, err := d.discoverLatestCID(did)
	if err != nil {
		return fmt.Errorf("failed to discover latest CID for did[%s]: %w", did, err)
	}

	return d.publisher.PublishDID(latestCID + docutil.NamespaceDelimiter + suffix)
}

func (d *Discovery) discoverLatestCID(did string) (string, error) {
	endpoint, err := d.endpointClient.GetEndpointFromAnchorOrigin(did)
	if err != nil {
		return "", fmt.Errorf("failed to get endpoints: %w", err)
	}

	logger.Debugf("discovered latest CID for did[%s]: +v", did, endpoint)

	return endpoint.AnchorURI, nil
}

// getOrbSuffix fetches unique portion of ID which is string after namespace.
// Valid Orb suffix has two parts cas hint + cid:suffix.
func (d *Discovery) getSuffix(did string) (string, error) {
	parts := strings.Split(did, docutil.NamespaceDelimiter)

	const minOrbIdentifierParts = 4
	if len(parts) < minOrbIdentifierParts {
		return "", fmt.Errorf("invalid number of parts[%d] for Orb identifier", len(parts))
	}

	return parts[len(parts)-1], nil
}
