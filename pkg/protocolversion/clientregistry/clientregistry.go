/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/context/common"
	versioncommon "github.com/trustbloc/orb/pkg/protocolversion/common"
	v1_0 "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/client"
)

var logger = log.New("client-factory-registry")

type factory interface {
	Create(version string, casClient common.CASReader) (common.ClientVersion, error)
}

const (
	// V1_0 ...
	V1_0 = "1.0"
)

// Registry implements a client version factory registry.
type Registry struct {
	factories map[string]factory
	mutex     sync.RWMutex
}

// New returns a new client version factory Registry.
func New() *Registry {
	logger.Debugf("Creating client version factory Registry")

	registry := &Registry{factories: make(map[string]factory)}

	// register supported versions
	registry.Register(V1_0, v1_0.New())

	return registry
}

// CreateClientVersion creates a new client version using the given version and providers.
func (r *Registry) CreateClientVersion(version string, casClient common.CASReader) (common.ClientVersion, error) {
	v, err := r.resolveFactory(version)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Creating client version [%s]", version)

	return v.Create(version, casClient)
}

// Register registers a client factory for a given version.
func (r *Registry) Register(version string, factory factory) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.factories[version]; ok {
		panic(fmt.Errorf("client version factory [%s] already registered", version))
	}

	logger.Debugf("Registering client version factory [%s]", version)

	r.factories[version] = factory
}

func (r *Registry) resolveFactory(version string) (factory, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for v, f := range r.factories {
		if versioncommon.Version(v).Matches(version) {
			return f, nil
		}
	}

	return nil, fmt.Errorf("client version factory for version [%s] not found", version)
}
