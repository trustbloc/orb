/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nsprovider

import (
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// New creates new client version provider per namespace.
func New() *Provider {
	return &Provider{clients: make(map[string]ClientVersionProvider)}
}

// ClientVersionProvider defines interface for accessing protocol version information.
type ClientVersionProvider interface {
	// Current returns latest client version.
	Current() (protocol.Version, error)

	// Get returns the client version at the given transaction time.
	Get(transactionTime uint64) (protocol.Version, error)
}

// Provider implements client version provider per namespace.
type Provider struct {
	mutex   sync.RWMutex
	clients map[string]ClientVersionProvider
}

// Add adds client version provider for namespace.
func (m *Provider) Add(namespace string, cvp ClientVersionProvider) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.clients[namespace] = cvp
}

// ForNamespace will return client version provider for that namespace.
func (m *Provider) ForNamespace(namespace string) (ClientVersionProvider, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	cvp, ok := m.clients[namespace]
	if !ok {
		return nil, fmt.Errorf("client version(s) not defined for namespace: %s", namespace)
	}

	return cvp, nil
}
