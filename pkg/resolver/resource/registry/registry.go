/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package registry

import (
	"fmt"
)

// Option is a registry instance option.
type Option func(opts *Registry)

// Registry contains providers for resource information.
type Registry struct {
	providers []ResourceInfoProvider
}

// ResourceInfoProvider defines interface for resource info providers.
type ResourceInfoProvider interface {
	GetResourceInfo(id string) (Metadata, error)
	Accept(id string) bool
}

// New return new instance of resource info providers registry.
func New(opts ...Option) *Registry {
	registry := &Registry{}

	// apply options
	for _, opt := range opts {
		opt(registry)
	}

	return registry
}

// GetResourceInfo provides information about resource.
func (r *Registry) GetResourceInfo(id string) (Metadata, error) {
	provider, err := r.resolveResourceInfoProvider(id)
	if err != nil {
		return nil, err
	}

	result, err := provider.GetResourceInfo(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource[%s] info: %w", id, err)
	}

	return result, nil
}

func (r *Registry) resolveResourceInfoProvider(id string) (ResourceInfoProvider, error) {
	for _, v := range r.providers {
		if v.Accept(id) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("resource '%s' not supported", id)
}

// WithResourceInfoProvider adds resource info provider to the list of available providers.
func WithResourceInfoProvider(p ResourceInfoProvider) Option {
	return func(opts *Registry) {
		opts.providers = append(opts.providers, p)
	}
}

// Metadata can contains various metadata for resource.
type Metadata map[string]interface{}

const (
	// AnchorOriginProperty is anchor origin key.
	AnchorOriginProperty = "anchorOrigin"

	// AnchorURIProperty is anchor URI key.
	AnchorURIProperty = "anchorURI"
)
