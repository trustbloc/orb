/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import (
	"fmt"
	"sync"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/context/common"
	versioncommon "github.com/trustbloc/orb/pkg/protocolversion/common"
)

var logger = log.New("client-factory-registry")

type factory interface {
	Create(version string, casClient common.CASReader, sidetreeCfg *config.Sidetree) (protocol.Version, error)
}

// Registry implements a client version factory registry.
type Registry struct {
	factories map[string]factory
	mutex     sync.RWMutex
}

// New returns a new client version factory Registry.
func New() *Registry {
	logger.Debug("Creating client version factory Registry")

	registry := &Registry{factories: make(map[string]factory)}

	addVersions(registry)

	return registry
}

// CreateClientVersion creates a new client version using the given version and providers.
func (r *Registry) CreateClientVersion(version string, casClient common.CASReader,
	sidetreeCfg *config.Sidetree) (protocol.Version, error) {
	v, err := r.resolveFactory(version)
	if err != nil {
		return nil, err
	}

	logger.Debug("Creating client version", logfields.WithVersion(version))

	return v.Create(version, casClient, sidetreeCfg)
}

// Register registers a client factory for a given version.
func (r *Registry) Register(version string, factory factory) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.factories[version]; ok {
		panic(fmt.Errorf("client version factory [%s] already registered", version))
	}

	logger.Debug("Registering client version factory", logfields.WithVersion(version))

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
