/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factoryregistry

import (
	"fmt"
	"sync"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/config"
	ctxcommon "github.com/trustbloc/orb/pkg/context/common"
	versioncommon "github.com/trustbloc/orb/pkg/protocolversion/common"
)

var logger = log.NewStructured("factory-registry")

type factory interface {
	Create(version string, casClient cas.Client, casResolver ctxcommon.CASResolver, opStore ctxcommon.OperationStore,
		provider storage.Provider, sidetreeCfg *config.Sidetree) (protocol.Version, error)
}

// Registry implements a protocol version factory registry.
type Registry struct {
	factories map[string]factory
	mutex     sync.RWMutex
}

// New returns a new protocol version factory Registry.
func New() *Registry {
	logger.Info("Creating protocol version factory Registry")

	registry := &Registry{factories: make(map[string]factory)}

	// register supported versions
	addVersions(registry)

	return registry
}

// CreateProtocolVersion creates a new protocol version using the given version and providers.
func (r *Registry) CreateProtocolVersion(version string, casClient cas.Client, casResolver ctxcommon.CASResolver,
	opStore ctxcommon.OperationStore, provider storage.Provider,
	sidetreeCfg *config.Sidetree) (protocol.Version, error) {
	v, err := r.resolveFactory(version)
	if err != nil {
		return nil, err
	}

	logger.Info("Creating protocol version", log.WithVersion(version))

	return v.Create(version, casClient, casResolver, opStore, provider, sidetreeCfg)
}

// Register registers a protocol factory for a given version.
func (r *Registry) Register(version string, factory factory) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.factories[version]; ok {
		panic(fmt.Errorf("protocol version factory [%s] already registered", version))
	}

	logger.Info("Registering protocol version factory", log.WithVersion(version))

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

	return nil, fmt.Errorf("protocol version factory for version [%s] not found", version)
}
