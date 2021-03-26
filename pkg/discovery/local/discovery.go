/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

// New creates new local discovery.
func New(didCh chan []string) *Discovery {
	return &Discovery{didCh: didCh}
}

// Discovery implements local did discovery.
type Discovery struct {
	didCh chan []string
}

// RequestDiscovery requests did discovery.
func (d *Discovery) RequestDiscovery(did string) error {
	d.didCh <- []string{did}

	return nil
}
