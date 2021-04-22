/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factoryregistry

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	"github.com/trustbloc/orb/pkg/config"
	ctxcommon "github.com/trustbloc/orb/pkg/context/common"
	versioncommon "github.com/trustbloc/orb/pkg/protocolversion/common"
	v1_0 "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/factory"
)

var logger = log.New("factory-registry")

type factory interface {
	Create(version string, casClient cas.Client, opStore ctxcommon.OperationStore, anchorGraph ctxcommon.AnchorGraph, sidetreeCfg config.Sidetree) (protocol.Version, error) //nolint: lll
}

const (
	// V1_0 ...
	V1_0 = "1.0"
)

// Registry implements a protocol version factory registry.
type Registry struct {
	factories map[string]factory
	mutex     sync.RWMutex
}

// New returns a new protocol version factory Registry.
func New() *Registry {
	logger.Infof("Creating protocol version factory Registry")

	registry := &Registry{factories: make(map[string]factory)}

	// register supported versions
	registry.Register(V1_0, v1_0.New())

	return registry
}

// CreateProtocolVersion creates a new protocol version using the given version and providers.
func (r *Registry) CreateProtocolVersion(version string, casClient cas.Client, opStore ctxcommon.OperationStore,
	anchorGraph ctxcommon.AnchorGraph, sidetreeCfg config.Sidetree) (protocol.Version, error) {
	v, err := r.resolveFactory(version)
	if err != nil {
		return nil, err
	}

	logger.Infof("Creating protocol version [%s]", version)

	return v.Create(version, casClient, opStore, anchorGraph, sidetreeCfg) // nolint: wrapcheck
}

// Register registers a protocol factory for a given version.
func (r *Registry) Register(version string, factory factory) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.factories[version]; ok {
		panic(fmt.Errorf("protocol version factory [%s] already registered", version))
	}

	logger.Infof("Registering protocol version factory [%s]", version)

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
