/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"
)

// New creates new protocol client provider.
func New() *ClientProvider {
	return &ClientProvider{clients: make(map[string]protocol.Client)}
}

// ClientProvider implements mock protocol client provider.
type ClientProvider struct {
	mutex   sync.RWMutex
	clients map[string]protocol.Client
}

// Add adds protocol client for namespace.
func (m *ClientProvider) Add(namespace string, pc protocol.Client) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.clients[namespace] = pc
}

// ForNamespace will return protocol client for that namespace.
func (m *ClientProvider) ForNamespace(namespace string) (protocol.Client, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	pc, ok := m.clients[namespace]
	if !ok {
		return nil, fmt.Errorf("protocol client not defined for namespace: %s", namespace)
	}

	return pc, nil
}
