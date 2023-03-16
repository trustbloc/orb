/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package noop

import "context"

// New creates new noop discovery.
func New() *Discovery {
	return &Discovery{}
}

// Discovery implements noop did discovery.
type Discovery struct{}

// RequestDiscovery requests did discovery.
func (*Discovery) RequestDiscovery(ctx context.Context, id string) error {
	return nil
}
