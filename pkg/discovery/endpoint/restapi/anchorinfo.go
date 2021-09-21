/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"fmt"

	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
)

// AnchorInfo contains information about an anchor credential.
type AnchorInfo struct {
	AnchorOrigin       string
	AnchorURI          string
	CanonicalReference string
}

// AnchorInfoRetriever retrieves anchor information about a DID.
type AnchorInfoRetriever struct {
	resourceRegistry *registry.Registry
}

// NewAnchorInfoRetriever returns a new AnchorInfoRetriever.
func NewAnchorInfoRetriever(r *registry.Registry) *AnchorInfoRetriever {
	return &AnchorInfoRetriever{resourceRegistry: r}
}

// GetAnchorInfo returns anchor information about the given DID.
func (r *AnchorInfoRetriever) GetAnchorInfo(did string) (*AnchorInfo, error) {
	// TODO (#537): Show IPFS alternates if configured.
	metadata, err := r.resourceRegistry.GetResourceInfo(did)
	if err != nil {
		return nil, fmt.Errorf("get info for DID [%s]: %w", did, err)
	}

	info := &AnchorInfo{}

	info.AnchorOrigin, err = r.getProperty(registry.AnchorOriginProperty, metadata, true)
	if err != nil {
		return nil, fmt.Errorf("get anchor origin for DID [%s]: %w", did, err)
	}

	info.AnchorURI, err = r.getProperty(registry.AnchorURIProperty, metadata, true)
	if err != nil {
		return nil, fmt.Errorf("get anchor URI for DID [%s]: %w", did, err)
	}

	info.CanonicalReference, err = r.getProperty(registry.CanonicalReferenceProperty, metadata, false)
	if err != nil {
		return nil, fmt.Errorf("get canonical ID for DID [%s]: %w", did, err)
	}

	return info, nil
}

func (r *AnchorInfoRetriever) getProperty(property string, metadata registry.Metadata, required bool) (string, error) {
	rawValue, ok := metadata[property]
	if !ok {
		if !required {
			return "", nil
		}

		return "", fmt.Errorf("property required [%s]", property)
	}

	value, ok := rawValue.(string)
	if !ok {
		return "", fmt.Errorf("could not assert property as a string [%s]", property)
	}

	if value == "" && required {
		return "", fmt.Errorf("property required [%s]", property)
	}

	return value, nil
}
