/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

type didPublisher interface {
	PublishDID(dids string) error
}

// New creates new local discovery.
func New(didPublisher didPublisher) *Discovery {
	return &Discovery{publisher: didPublisher}
}

// Discovery implements local did discovery.
type Discovery struct {
	publisher didPublisher
}

// RequestDiscovery requests did discovery.
func (d *Discovery) RequestDiscovery(did string) error {
	return d.publisher.PublishDID(did)
}
